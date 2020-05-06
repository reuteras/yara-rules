#!/bin/bash

[[ ! -d total ]] && mkdir total

find -E misc sub -regex ".*\.yara?" | \
    # Remove rules specific for LOKI and SPARK, https://github.com/Neo23x0/signature-base#external-variables-in-yara-rules
    grep -Ev "yara/(generic_anomalies|general_cloaking|thor_inverse_matches|yara_mixed_ext_vars)\.yar" | \
    # Remove duplicte rules
    grep -vE "malware-ioc/turla/(carbon|gazer)\.yar" | \
    grep -vE "malware-ioc/groundbait/prikormka.yar" | \
    grep -vE "Malware-Misc-RE/2020-04-18-maze-ransomware-unpacked-payload.vk.yar" | \
    # Remove file with <fs>...</fs> tag
    grep -vE "Malware-Misc-RE/2020-03-27-dridex-worker-config-software-banking-yara.vk.yar" | \
    # Remove files with errors
    grep -vE "Malware-Misc-RE/2020-04-07-qbot-qsort-miniupnp-vk.yar" | \
    grep -vE "Malware-Misc-RE/2020-03-19-netwalker-yara-config-yar-vk.yar" | \
    xargs cat > total/total.yara
