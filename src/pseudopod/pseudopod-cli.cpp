// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <list>
#include <getopt.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>

extern "C" {
#include <pseudo/pseudo.h>
#include "userns.h"
}

// -------------------- Utilities and C resource helpers --------------------

static inline ns_entry_t* allocate_and_copy(const std::vector<ns_entry_t>& src) {
    if (src.empty()) return nullptr;
    ns_entry_t* buf = new (std::nothrow) ns_entry_t[src.size()];
    if (!buf) return nullptr;
    std::copy(src.begin(), src.end(), buf);
    return buf;
}

static int update_pmi_fd() {
    char* pmi_fd_opt = ::getenv("PMI_FD");
    if (!pmi_fd_opt) {
        return 1;
    }
    const std::string pmi_fd_str{pmi_fd_opt};

    char* endp = nullptr;
    errno = 0;
    long parsed = std::strtol(pmi_fd_str.c_str(), &endp, 10);
    if (errno != 0 || endp == pmi_fd_str.c_str() || *endp != '\0' || parsed < 3) {
        std::fprintf(stderr, "update_pmi_fd: PMI_FD value is invalid: '%s'\n", pmi_fd_str.c_str());
        return 1;
    }
    int old_fd = static_cast<int>(parsed);

    int new_fd = ::dup(old_fd);
    if (new_fd < 0) {
        std::fprintf(stderr, "update_pmi_fd: dup(%d) failed: %s\n", old_fd, std::strerror(errno));
        return 1;
    }

    if (::close(old_fd) < 0) {
        std::fprintf(stderr, "update_pmi_fd: close(%d) failed: %s\n", old_fd, std::strerror(errno));
    }

    if (!::setenv("PMI_FD", std::to_string(new_fd).c_str(), 1)) {
        return 1;
    }

    std::string preserve = std::string("--preserve-fds=") + std::to_string(new_fd - 2);
    if (!::setenv("PRESERVE_FDS", preserve.c_str(), 1)) {
        return 1;
    }

    return 0;
}

static inline int mount_tmpfs_path(const char* path) {
    if (!path || !*path) {
        std::fprintf(stderr, "mount tmpfs: invalid path\n");
        return -1;
    }
    if (mount("tmpfs", path, "tmpfs", 0, 0) < 0) {
        perror("mount tmpfs");
        return -1;
    }
    return 0;
}

// -------------------- Child callback --------------------

struct ChildCtx {
    cb_podman_envars_config_t podman_env{};
    const std::list<std::string>* tmpfs_paths{};
    int mount_run{1};
};

static int cb_child_set_podman_envars_and_mount(void* args) {
    if (!args) return -1;
    auto* ctx = static_cast<ChildCtx*>(args);

    int rv = cb_set_podman_envars(&ctx->podman_env);
    if (rv != 0) return rv;

    update_pmi_fd();

    for (const auto& p : *ctx->tmpfs_paths) {
        if (mount_tmpfs_path(p.c_str()) != 0) {
            std::fprintf(stderr, "Failed to mount tmpfs at %s\n", p.c_str());
            return -1;
        }
    }

    return 0;
}

// -------------------- Subcommands and usage --------------------

enum class Subcmd { Auto, Virtual, Subuid, Fakeroot };

static int starts_with_icase(const char* full, const char* prefix) {
    while (*full && *prefix) {
        unsigned char a = (unsigned char) *(full++);
        unsigned char b = (unsigned char) *(prefix++);
        if (tolower(a) != tolower(b)) {
            return 0;
        }
    }
    return *prefix == '\0';
}

static const char* resolve_subcommand(const char* token) {
    if (!token || !*token) return nullptr;
    switch (tolower((unsigned char)token[0])) {
        case 'a': return starts_with_icase("auto", token) ? "auto" : nullptr;
        case 'v': return starts_with_icase("virtual", token) ? "virtual" : nullptr;
        case 's': return starts_with_icase("subuid", token) ? "subuid" : nullptr;
        case 'f': return starts_with_icase("fakeroot", token) ? "fakeroot" : nullptr;
        default:  return nullptr;
    }
}

static void usage(const char* argv0) {
    std::fprintf(stderr,
        "Usage: %s <subcommand> [OPTIONS] <target> [args...]\n"
        "If no subcommand is provided, 'auto' is used.\n"
        "If no <target> is provided, the user's shell ($SHELL or /bin/sh) is run.\n"
        "\n"
        "Subcommands (minimal unambiguous prefixes accepted, case insensitive):\n"
        "  auto        Auto-select based on subuid availability\n"
        "  subuid      Use privileged user namespace, no virtualization\n"
        "  virtual     Enable UID virtualization in an unprivileged user namespace\n"
        "  fakeroot    Seccomp fakeroot emulation in an unprivileged user namespace (no virtualization)\n"
        "\n"
        "Global options:\n"
        "  -r, --mount-run=on|off      Mount tmpfs at /run/user  (default on)\n"
        "  -t, --mount-tmpfs=<path>    Mount a tmpfs at the specified path. May be specified multiple times.\n"
        "  -d, --debug                 Enable debug output\n"
        "  -h, --help                  Show this help\n"
        "\n"
        "virtual options:\n"
        "  -v, --tracer=on|off         Install tracer seccomp profile (default on)\n",
        argv0
    );
}

// -------------------- Argument parsing --------------------

struct ArgOptions {
    Subcmd subcmd{Subcmd::Auto};
    int tracer_on{1};          // only relevant in Virtual
    int mount_run{1};
    std::list<std::string> tmpfs_paths;
    char** targv{nullptr};
    bool help_requested{false};
};

// build argv copy that excludes a specific index
static std::unique_ptr<char*, void(*)(void*)> argv_without_index(int argc, char** argv, int drop_idx, int& out_argc) {
    int new_argc = argc - (drop_idx >= 0 ? 1 : 0);
    if (new_argc <= 0) {
        out_argc = 0;
        return {nullptr, free};
    }
    char** new_argv = static_cast<char**>(std::calloc(static_cast<size_t>(new_argc), sizeof(char*)));
    if (!new_argv) {
        perror("alloc argv");
        out_argc = 0;
        return {nullptr, free};
    }
    int j = 0;
    for (int i = 0; i < argc; ++i) {
        if (i == drop_idx) continue;
        new_argv[j++] = argv[i];
    }
    out_argc = new_argc;
    return {new_argv, free};
}

int parse_args(int argc, char* argv[], ArgOptions& out) {
    // is subcommand in original argv?
    int subcmd_idx = -1;
    const char* subcmd_resolved = nullptr;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--") == 0) break;
        if (argv[i][0] == '-') continue;
        const char* r = resolve_subcommand(argv[i]);
        if (r) {
            subcmd_resolved = r;
            subcmd_idx = i;
            break;
        } else {
            // first non-option is not a subcommand, treat as start of target argv
            break;
        }
    }
    if (subcmd_resolved) {
        if      (!strcasecmp(subcmd_resolved, "auto"))      out.subcmd = Subcmd::Auto;
        else if (!strcasecmp(subcmd_resolved, "subuid"))    out.subcmd = Subcmd::Subuid;
        else if (!strcasecmp(subcmd_resolved, "virtual"))   out.subcmd = Subcmd::Virtual;
        else if (!strcasecmp(subcmd_resolved, "fakeroot"))  out.subcmd = Subcmd::Fakeroot;
    }

    // Build argv without subcommand for getopt_long
    int pargc = argc;
    char** pargv = argv;
    auto pargv_owned = argv_without_index(argc, argv, subcmd_idx, pargc);
    if (pargv_owned.get()) {
        pargv = pargv_owned.get();
    }

    static option opts[] = {
        {"tracer",      required_argument, 0, 'v'},
        {"mount-run",   required_argument, 0, 'r'},
        {"mount-tmpfs", required_argument, 0, 't'},
        {"help",        no_argument,       0, 'h'},
        {0,0,0,0}
    };
    const char* optstring = "+v:r:t:h";

    opterr = 1;
    optind = 1;
    int opt;
    while ((opt = getopt_long(pargc, pargv, optstring, opts, nullptr)) != -1) {
        switch (opt) {
            case 'r':
                if (!std::strcmp(optarg, "on"))       out.mount_run = 1;
                else if (!std::strcmp(optarg, "off")) out.mount_run = 0;
                else {
                    std::fprintf(stderr, "Invalid value for --mount-run: %s (use on or off)\n", optarg);
                    return 1;
                }
                break;
            case 't':
                if (!optarg || !*optarg || optarg[0] != '/') {
                    std::fprintf(stderr, "Invalid value for --mount-tmpfs: absolute path required\n");
                    return 1;
                }
                out.tmpfs_paths.emplace_back(optarg);
                break;
            case 'v':
                if (out.subcmd != Subcmd::Virtual) {
                    std::fprintf(stderr, "--tracer is only valid with 'virtual'\n");
                    return 1;
                }
                if (!std::strcmp(optarg, "on"))       out.tracer_on = 1;
                else if (!std::strcmp(optarg, "off")) out.tracer_on = 0;
                else {
                    std::fprintf(stderr, "Invalid value for --tracer: %s (use on or off)\n", optarg);
                    return 1;
                }
                break;
            case 'h':
            default:
                usage(argv[0]);
                out.help_requested = true;
                return 1;
        }
    }

    if (out.mount_run) {
        out.tmpfs_paths.emplace_front("/run/user/");
    }

    // targv computation uses original argv
    out.targv = &argv[optind + (subcmd_resolved != nullptr)];

    // Default target to shell if none provided
    if (optind >= pargc) {
        static char* default_argv[2] = {nullptr, nullptr};
        char* shell = std::getenv("SHELL");
        if (!shell || !*shell) shell = const_cast<char*>("/bin/sh");
        default_argv[0] = shell;
        out.targv = default_argv;
    }
    return 0;
}

// -------------------- User namespace configuration --------------------

class UsernsConfigurator {
    setup_userns_config_t cfg{};
    bool priv_avail;

    void free() {
        auto& uident = this->cfg.uid_config.entries;
        auto& gident = this->cfg.gid_config.entries;
        if (uident) { delete[] uident; uident = nullptr; }
        if (gident) { delete[] gident; gident = nullptr; }
    }
public:

    ~UsernsConfigurator() {
        this->free();
    }

    UsernsConfigurator() {
        this->priv_avail = 0;
        std::vector<ns_entry_t> uid_entries, gid_entries;

        uid_entries.emplace_back(ns_entry_t{0u, static_cast<uint32_t>(getuid()), 1u});
        gid_entries.emplace_back(ns_entry_t{0u, static_cast<uint32_t>(getgid()), 1u});
        auto& uid_cfg = this->cfg.uid_config;
        auto& gid_cfg = this->cfg.gid_config;
        uid_cfg.num_entries = gid_cfg.num_entries = 1;

        subid_range_t uid_range{}, gid_range{};
        int rc = get_subid_config(&uid_range, &gid_range);
        if (rc != 0 || uid_range.count < 1004 || gid_range.count < 1004) {
            // unpriv only
        } else {
            this->priv_avail = 1;
            if (uid_range.count < 65536 || gid_range.count < 65536) {
                uid_cfg.num_entries = gid_cfg.num_entries = 3;
                uid_entries.emplace_back(ns_entry_t{1u, uid_range.subid, uid_range.count - 2u});
                gid_entries.emplace_back(ns_entry_t{1u, gid_range.subid, gid_range.count - 2u});
                uid_entries.emplace_back(ns_entry_t{65534u, uid_range.subid + uid_range.count - 2u, 2u});
                gid_entries.emplace_back(ns_entry_t{65534u, gid_range.subid + gid_range.count - 2u, 2u});
            } else {
                uid_cfg.num_entries = gid_cfg.num_entries = 2;
                uid_entries.emplace_back(ns_entry_t{1u, uid_range.subid, uid_range.count});
                gid_entries.emplace_back(ns_entry_t{1u, gid_range.subid, gid_range.count});
            }
        }

        uid_cfg.entries = allocate_and_copy(uid_entries);
        gid_cfg.entries = allocate_and_copy(gid_entries);
        if (!uid_cfg.entries || !gid_cfg.entries) {
            std::fprintf(stderr, "UsernsConfigurator: allocation failed\n");
            this->free();
            this->priv_avail = 0;
        }
    }

    const setup_userns_config_t* get_cfg() const {
        return &this->cfg;
    }

    bool privileged_available() const {
        return this->priv_avail;
    }
};

// -------------------- Runtime planning --------------------

class RuntimePlan {
    int virt_enabled{0};
    int fakeroot_mode{0};
    int tracer_on{1};

    int (*parent_cb)(pid_t, void*){nullptr};
    UsernsConfigurator userns;
    const seccomp_fprog* filters[3]{nullptr, nullptr, nullptr};
    ChildCtx child_ctx{};
    char** targv{nullptr};

    struct ArgOptions& args;
    id_state_t base_id{ {{0, 0, 0}, {0, 0, 0}} };
public:
    RuntimePlan(struct ArgOptions& args) : args(args) {
        this->tracer_on = args.tracer_on;
        this->targv = args.targv;

        bool priv_avail = this->userns.privileged_available();

        Subcmd chosen = args.subcmd;
        if (chosen == Subcmd::Auto) {
            chosen = priv_avail ? Subcmd::Subuid : Subcmd::Virtual;
            if (chosen == Subcmd::Virtual) this->tracer_on = 1;
        }

        switch (chosen) {
            case Subcmd::Subuid:
                if (!priv_avail) {
                    std::fprintf(stderr, "Privileged user namespace mapping not available. Use 'virtual' subcommand.\n");
                    // Signal invalid by leaving parent_cb null
                    this->parent_cb = nullptr;
                    return;
                }
                this->parent_cb = cb_setup_userns_priv;
                this->virt_enabled = 0;
                this->fakeroot_mode = 0;
                break;

            case Subcmd::Virtual:
                this->parent_cb = cb_setup_userns_unpriv;
                this->virt_enabled = 1;
                this->fakeroot_mode = 0;
                break;

            case Subcmd::Fakeroot:
                this->parent_cb = cb_setup_userns_unpriv;
                this->virt_enabled = 0;
                this->fakeroot_mode = 1;
                break;
            default:
                break;
        }

        // filters
        if (this->fakeroot_mode) {
            this->filters[0] = get_filter_fakeroot();
            this->filters[1] = get_filter_fakechown();
        } else if (this->virt_enabled) {
            if (this->tracer_on) {
                this->filters[0] = get_filter_trace();
                this->filters[1] = get_filter_fakechown();
            }
        }

        // child ctx
        this->child_ctx.podman_env.uid = getuid();
        this->child_ctx.podman_env.gid = getgid();
        this->child_ctx.tmpfs_paths = &this->args.tmpfs_paths;
        this->child_ctx.mount_run = this->args.mount_run;
    }

    int run() const {
        if (!this->parent_cb) {
            return EXIT_FAILURE;
        }

        const setup_userns_config_t* parent_cbargs = this->userns.get_cfg();
        if (!parent_cbargs->uid_config.entries || !parent_cbargs->gid_config.entries) {
            return EXIT_FAILURE;
        }

        pseudo_config_t cfg;
        pseudo_init_config(&cfg);

        cfg.cfg_parent.base_id       = this->base_id;
        cfg.cfg_parent.virt_enabled  = this->virt_enabled;
        pseudo_cb_add(&cfg.cfg_parent.cbs,
                      (void*) this->parent_cb,
                      const_cast<setup_userns_config_t*>(parent_cbargs)
                      );

        cfg.cfg_child.clone_flags    = CLONE_NEWNS | CLONE_NEWUSER;
        cfg.cfg_child.child_argv     = this->targv;
        cfg.cfg_child.child_envp     = nullptr;
        cfg.cfg_child.filters        = (const seccomp_fprog**) this->filters;
        pseudo_cb_add(&cfg.cfg_child.cbs,
                      (void*)&cb_child_set_podman_envars_and_mount,
                      const_cast<ChildCtx*>(&this->child_ctx)
                      );

        int child_rv = pseudo_run(&cfg);
        return child_rv == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }
};

// -------------------- main --------------------

int main(int argc, char* argv[]) {
    ArgOptions options{};
    if (parse_args(argc, argv, options) != 0) {
        // usage already printed if needed
        return EXIT_FAILURE;
    }

    RuntimePlan plan(options);

    return plan.run();
}
