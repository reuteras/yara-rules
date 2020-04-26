#!/bin/bash

[[ ! -d total ]] && mkdir total

find -E misc sub -regex ".*\.yara?" | \
    # Remove rules specific for LOKI and SPARK, https://github.com/Neo23x0/signature-base#external-variables-in-yara-rules
    grep -Ev "yara/(generic_anomalies|general_cloaking|thor_inverse_matches|yara_mixed_ext_vars)\.yar" | \
    # Remove duplicte rules
    grep -vE "malware-ioc/turla/(carbon|gazer)\.yar" | \
    grep -vE "malware-ioc/groundbait/prikormka.yar" | \
    xargs cat > total/total.yara
