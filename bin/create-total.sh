#!/bin/bash

[[ ! -d total ]] && mkdir total

find -E misc sub -regex ".*\.yara?" -print0 | \
    # Remove rules specific for LOKI and SPARK, https://github.com/Neo23x0/signature-base#external-variables-in-yara-rules
    sed -E "s#sub/signature-base/yara/(generic_anomalies|general_cloaking|thor_inverse_matches|yara_mixed_ext_vars)\.yar##g" | \
    sed -E "s#sub/signature-base/yara/apt_turla_penquin.yar##" | \
    # Remove duplicte rules
    sed -E "s#sub/malware-ioc/turla/(carbon|gazer)\.yar##g" | \
    sed -E "s#sub/malware-ioc/groundbait/prikormka.yar##" | \
    sed -E "s#sub/Malware-Misc-RE/2020-04-18-maze-ransomware-unpacked-payload.vk.yar##" | \
    # Remove file with <fs>...</fs> tag
    sed -E "s#sub/Malware-Misc-RE/2020-03-27-dridex-worker-config-software-banking-yara.vk.yar##" | \
    # Remove files with errors
    sed -E "s#sub/Malware-Misc-RE/2020-04-07-qbot-qsort-miniupnp-vk.yar##" | \
    sed -E "s#sub/Malware-Misc-RE/2020-03-19-netwalker-yara-config-yar-vk.yar##" | \
    sed -E "s#sub/APT_REPORT/Turla/2017/PENQUIN_MOONLIT_MAZE.yara##" | \
    sed -E "s#sub/APT_REPORT/APT28/yara/APT28.yar##" | \
    sed -E "s#sub/APT_REPORT/Oceanlotus/oceanlotus_png_loader.yar##" | \
    tr -d '\n' | \
    xargs -0 cat > total/total.yara
