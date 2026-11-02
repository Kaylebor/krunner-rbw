bin_dir := env("HOME") / ".local/bin"
data_dir := env("XDG_DATA_HOME", env("HOME") / ".local/share")

build:
    cargo build --release

# Install the binary, KRunner plugin file and D-Bus activation file, then restart KRunner.
install: build
    install -Dm755 target/release/krunner-rbw {{bin_dir}}/krunner-rbw
    install -Dm644 data/krunner-rbw.desktop {{data_dir}}/krunner/dbusplugins/krunner-rbw.desktop
    mkdir -p {{data_dir}}/dbus-1/services
    sed 's|@BIN@|{{bin_dir}}/krunner-rbw|' data/local.krunner_rbw.service.in > {{data_dir}}/dbus-1/services/local.krunner_rbw.service
    just reload

# Restart the runner and KRunner so they pick up changes.
reload:
    -pkill -x krunner-rbw
    -kquitapp6 krunner

uninstall:
    -pkill -x krunner-rbw
    rm -f {{bin_dir}}/krunner-rbw {{data_dir}}/krunner/dbusplugins/krunner-rbw.desktop {{data_dir}}/dbus-1/services/local.krunner_rbw.service
    -kquitapp6 krunner
