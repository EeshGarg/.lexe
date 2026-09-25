#!/usr/bin/env bash
# 01 — install and launch.
#
# Definitive Architecture acceptance criteria covered here:
#   * "Verify package identity, hashes, signature, package role, entrypoint
#      type, and declared ISA."
#   * "Install the payload into the internal .LEXE application store; do not
#      expose the raw ELF as the normal desktop launcher."
#   * "Create durable MIME/desktop/icon integration and a first-class run.lexe
#      launch reference."
#   * "...launch the GUI through lexe; no raw ELF decision or terminal prompt
#      appears."
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

acc_begin "01 install and launch"
acc_require_binaries
acc_scratch_home
acc_build_package

# ----------------------------------------------------------------- verify
verify_json="$ACC_ROOT/work/verify.json"
"$LEXE" verify "$ACC_PACKAGE" --json >"$verify_json"

acc_equals "$(acc_json "$verify_json" 'd["ok"]')" "True" "package verifies end to end"
acc_equals "$(acc_json "$verify_json" 'd["signatureState"]')" "valid" "signature state is valid"
acc_true "$([[ -n "$(acc_json "$verify_json" 'd["fingerprint"]["short"]')" ]] && echo 0 || echo 1)" \
    "package identity carries a publisher key fingerprint"

# Every stage the criteria name must be present AND passing.
for stage in structure manifest key manifest-signature payload-signature hashes payload-role; do
    present="$(acc_json "$verify_json" "any(s['name'] == '$stage' for s in d['stages'])")"
    ok="$(acc_json "$verify_json" "all(s['ok'] for s in d['stages'] if s['name'] == '$stage')")"
    if [[ "$present" == "True" && "$ok" == "True" ]]; then
        pass "verification stage \"$stage\" is present and passing"
    else
        fail "verification stage \"$stage\" is present and passing" "present=$present ok=$ok"
    fi
done

# payload-role is the stage that proves entrypoint type + declared ISA.
role_detail="$(acc_json "$verify_json" "[s['detail'] for s in d['stages'] if s['name']=='payload-role'][0]")"
acc_contains "$role_detail" 'role "application"' "payload-role reports the declared package role"
acc_contains "$role_detail" "runnable ELF" "payload-role proves the entrypoint is a runnable ELF"
acc_contains "$role_detail" "declared architecture" "payload-role checks the declared ISA"

# The manifest really does declare the GUI launch mode + native-only policy.
manifest_json="$ACC_ROOT/work/manifest.json"
"$LEXE" inspect "$ACC_PACKAGE" --manifest >"$manifest_json"
acc_equals "$(acc_json "$manifest_json" 'd["launch"]["mode"]')" "gui" 'manifest declares launch.mode = "gui"'
acc_equals "$(acc_json "$manifest_json" 'd["role"]')" "application" 'manifest declares role = "application"'
acc_equals "$(acc_json "$manifest_json" 'str(d["execution"]["allowedChains"])')" "['native']" \
    'manifest declares execution.allowedChains = ["native"]'

# ---------------------------------------------------------------- install
acc_install_package

payload="$(acc_version_dir)/$ACC_ENTRYPOINT"
acc_file_exists "$payload" "payload ELF is installed inside the .LEXE application store"
acc_true "$([[ -x "$payload" ]] && echo 0 || echo 1)" "installed entrypoint is executable"
acc_contains "$(file -b "$payload")" "ELF 64-bit" "installed entrypoint really is an ELF object"

# The raw ELF must NOT be the desktop launch object.
entry="$(acc_desktop_entry)"
acc_file_exists "$entry" "a .desktop entry was created for the application"
exec_line="$(grep -m1 '^Exec=' "$entry" || true)"
acc_equals "$exec_line" "Exec=lexe run $ACC_APP_ID" ".desktop Exec is \`lexe run <id>\`, not a path to the ELF"
acc_true "$(grep -q "$(acc_version_dir)" "$entry" && echo 1 || echo 0)" \
    ".desktop entry does not mention the payload path anywhere"
acc_equals "$(grep -m1 '^Terminal=' "$entry" || true)" "Terminal=false" \
    "the GUI application's .desktop entry asks for no terminal"

# Icons.
icon_count=0
for d in 64x64 128x128 256x256 scalable; do
    if compgen -G "$LEXE_HOME/icons/hicolor/$d/apps/lexe-$ACC_APP_ID.*" >/dev/null; then
        icon_count=$((icon_count + 1))
    fi
done
acc_equals "$icon_count" "4" "all four packaged icon sizes landed in the hicolor theme"

# The MIME type + persistent default association (what survives a reboot).
acc_file_exists "$LEXE_HOME/mime/packages/lexe.xml" "the .lexe shared-mime-info type is registered"
acc_file_exists "$LEXE_HOME/applications/lexe-handler.desktop" "the .LEXE runtime handler entry is registered"
acc_contains "$(cat "$(acc_mimeapps)")" "application/vnd.usha.lexe=lexe-handler.desktop" \
    "mimeapps.list records a persistent default association for .lexe"

# ------------------------------------------------------ run.lexe reference
ref="$(acc_launch_ref)"
acc_file_exists "$ref" "<LEXE_HOME>/launch/<id>.lexe launch reference exists"
ref_json="$ACC_ROOT/work/verify-ref.json"
"$LEXE" verify "$ref" --json >"$ref_json"
acc_equals "$(acc_json "$ref_json" 'd["ok"]')" "True" "lexe verify accepts the launch reference"
ref_role="$(acc_json "$ref_json" "[s['detail'] for s in d['stages'] if s['name']=='payload-role'][0]")"
acc_contains "$ref_role" 'role "launch"' "the launch reference verifies with role \"launch\""
acc_contains "$ref_role" "$ACC_APP_ID" "the launch reference names the installed application"
acc_contains "$ref_role" "no payload" "the launch reference carries no payload of its own"

# ------------------------------------------------------- integration.json
integration="$(acc_integration)"
acc_file_exists "$integration" "integration.json records what .LEXE owns"
kinds="$(acc_json "$integration" "sorted({a['kind'] for a in d['artifacts']})")"
for kind in runtime-mime runtime-handler app-desktop-entry app-icon launch-reference; do
    acc_contains "$kinds" "$kind" "integration.json lists a \"$kind\" artifact"
done
owned="$(acc_json "$integration" "sum(1 for a in d['artifacts'] if a['app'] == '$ACC_APP_ID')")"
acc_equals "$owned" "6" "integration.json attributes 6 artifacts to the app (entry + 4 icons + run.lexe)"
missing="$(acc_json "$integration" "[a['path'] for a in d['artifacts'] if not __import__('os').path.isfile(a['path'])]")"
acc_equals "$missing" "[]" "every artifact integration.json records is present on disk"

# doctor agrees that the freshly installed state is healthy.
if "$LEXE" doctor --json >"$ACC_ROOT/work/doctor.json" 2>/dev/null; then
    acc_equals "$(acc_json "$ACC_ROOT/work/doctor.json" 'd["ok"]')" "True" "lexe doctor reports healthy integration after install"
else
    fail "lexe doctor reports healthy integration after install" \
        "$(acc_json "$ACC_ROOT/work/doctor.json" 'd["problems"]' 2>/dev/null || echo "doctor failed") problem(s)"
fi

# ------------------------------------------------------------------- run
# Headless: the payload's own --selftest. Exit 0 is the contract, and it must
# come back without a terminal prompt or any raw-ELF decision.
run_out="$ACC_ROOT/work/run.out"
set +e
"$LEXE" run "$ACC_APP_ID" -- --selftest >"$run_out" 2>&1
run_status=$?
set -e
acc_equals "$run_status" "0" "\`lexe run $ACC_APP_ID -- --selftest\` exits 0"
acc_contains "$(cat "$run_out")" "selftest: PASS" "the payload ran and reported success"
acc_contains "$(cat "$run_out")" "LEXE_APP_ID  : $ACC_APP_ID" "LEXE_APP_ID reached the application"
acc_contains "$(cat "$run_out")" "LEXE_APP_DATA: /run/lexe/data" "the private data root was provided inside the sandbox"
acc_contains "$(cat "$run_out")" "app data     : OK" "the application wrote into its private data directory"
acc_file_exists "$(acc_app_data)/gui-hello-probe.txt" "the file the app wrote is visible in <LEXE_HOME>/data/<id>"

# No terminal was spawned and nothing asked a question: the run produced only
# the application's own output.
if grep -qiE '\[y/n\]|press enter|continue\?' "$run_out"; then
    fail "the launch asked no interactive question" "$(cat "$run_out")"
else
    pass "the launch asked no interactive question"
fi

# ------------------------------------------------------------- real GUI
# With a session display present, run the application for real (no --selftest)
# and assert it entered its GUI path and stayed up. `launch.mode: "gui"` is what
# binds the display socket into the sandbox; a package that did not declare it
# would get no display at all.
if acc_have_display; then
    gui_out="$ACC_ROOT/work/gui.out"
    set +e
    timeout 5 "$LEXE" run "$ACC_APP_ID" >"$gui_out" 2>&1
    gui_status=$?
    set -e
    acc_kill_app
    log="$(acc_app_data)/gui-hello-launches.log"
    if grep -q "mode=gui" "$log" 2>/dev/null; then
        pass "the application entered its GUI path under the sandbox"
    else
        fail "the application entered its GUI path under the sandbox" \
            "no mode=gui line in $log" "$(cat "$gui_out" 2>/dev/null || true)"
    fi
    if [[ $gui_status -eq 124 ]]; then
        pass "the GUI stayed running until the harness stopped it (a window was open)"
    else
        fail "the GUI stayed running until the harness stopped it" \
            "exit status $gui_status — the application terminated early" \
            "$(cat "$gui_out" 2>/dev/null || true)"
    fi
    if grep -qiE 'cannot open display|no display available|Gdk-.*(ERROR|CRITICAL)' "$gui_out"; then
        fail "the sandbox forwarded a usable display to the application" "$(cat "$gui_out")"
    else
        pass "the sandbox forwarded a usable display to the application"
    fi
else
    skip "no WAYLAND_DISPLAY/DISPLAY on this host — the real-window check needs a session (see REBOOT.md)"
fi

acc_summary
