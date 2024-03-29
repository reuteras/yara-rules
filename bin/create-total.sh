#!/bin/bash

[[ ! -d total ]] && mkdir total

rm total/total.yara

find -E misc sub -regex ".*\.yara?" -print0 | \
    # Remove rules specific for LOKI and SPARK, https://github.com/Neo23x0/signature-base#external-variables-in-yara-rules
    sed -E "s#sub/signature-base/yara/(generic_anomalies|general_cloaking|thor_inverse_matches|yara_mixed_ext_vars)\.yar##g" | \
    sed -E "s#sub/signature-base/yara/apt_turla_penquin.yar##" | \
    sed -E "s#sub/signature-base/yara/configured_vulns_ext_vars.yar##" | \
    sed -E "s#sub/signature-base/yara/expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar##" | \
    sed -E "s#sub/signature-base/yara/gen_fake_amsi_dll.yar##" | \
    sed -E "s#sub/signature-base/yara/gen_mal_3cx_compromise_mar23.yar##" | \
    sed -E "s#sub/signature-base/yara/gen_webshells.yar##" | \
    sed -E "s#sub/signature-base/yara/gen_webshells_ext_vars.yar##" | \
    sed -E "s#sub/signature-base/yara/yara-rules_vuln_drivers_strict_renamed.yar##" | \
    sed -E "s#sub/signature-base/yara/gen_vcruntime140_dll_sideloading.yar##" | \
    # Remove duplicte rules
    sed -E "s#sub/malware-ioc/turla/(carbon|gazer)\.yar##g" | \
    sed -E "s#sub/malware-ioc/groundbait/prikormka.yar##" | \
    sed -E "s#sub/Malware-Misc-RE/2020-04-18-maze-ransomware-unpacked-payload.vk.yar##" | \
    sed -E "s#sub/APT_REPORT/Turla/2017/PENQUIN_MOONLIT_MAZE.yara##" | \
    sed -E "s#sub/APT_REPORT/APT28/yara/APT28.yar##" | \
    sed -E "s#sub/APT_REPORT/Oceanlotus/oceanlotus_png_loader.yar##" | \
    sed -E "s#sub/Yara-Rules/mobile/MOBILE_pwndroid5_downloader.yar##" | \
    sed -E "s#sub/Yara-Rules/mobile/Android_SandroRat.yar##" | \
    sed -E "s#sub/Yara-Rules/mobile/Android_Clicker_G.yar##" | \
    sed -E "s#sub/Yara-Rules/mobile/Android_SpyAgent.yar##" | \
    sed -E "s#sub/Yara-Rules/APT/APT_Derusbi.yar##" | \
    sed -E "s#sub/DailyIOC/2020-04-29/Yara_Rule_APT_Bazar-April_2020_1.yar##" | \
    sed -E "s#sub/DailyIOC/2020-06-23/APT_Lazarus_Stealer_June_2020_1.yar##" | \
    sed -E "s#sub/DailyIOC/2020-06-26/Heinote_June_2020-1.yar##" | \
    sed -E "s#sub/DailyIOC/2020-07-23/Yara_Rule_APT_Lazarus_Stealer_July_2020_1.yar##" | \
    sed -E "s#sub/DailyIOC/2020-08-24/SideWinder/APT_SideWinder_NET_Loader_Aug_2020_1.yar##" | \
    sed -E "s#sub/DailyIOC/2020-08-26/APT_OilRig_2016.yar##" | \
    sed -E "s#sub/DailyIOC/2020-08-27/APT_Patchwork_Tool_CVE_2019-0808_1.yar##" | \
    sed -E "s#sub/DailyIOC/2020-09-14/SLoad/Mal_Loader_Sload_Sep-2020-1.yar##" | \
    sed -E "s#sub/DailyIOC/2021-03-17/APT_FIN8_BADHATCH_Mar_2021_1.yar##" | \
    sed -E "s#sub/Yara-Rules/ransomware/ransom_BlackKingDom.yar##" | \
    sed -E "s#sub/DailyIOC/2020-10-31/Ran_Egregor_Oct_2020_1 .yar##" | \
    sed -E "s#sub/DailyIOC/2021-05-03/APT27/APT_APT27_Enc_Hyperbro_Apr_2021_1.yara##" | \
    sed -E "s#sub/DailyIOC/2021-05-03/APT27/APT_APT27_Hyperbro_Apr_2021_1.yara##" | \
    sed -E "s#sub/DailyIOC/2021-06-18/Netfilter/MAL_Netfilter_Dropper_Jun_2021_1.yara##" | \
    sed -E "s#sub/DailyIOC/2021-06-18/Netfilter/MAL_Netfilter_May_2021_1.yara##" | \
    # Remove slow rules
    sed -E "s#sub/GCTI/YARA/CobaltStrike/CobaltStrike__Resources_Artifact32svc_Exe_v1_49_to_v4_x.yara##" | \
    sed -E "s#sub/protections-artifacts/yara/rules/Windows_Trojan_CobaltStrike.yar##" | \
    # Remove file with <fs>...</fs> tag
    sed -E "s#sub/Malware-Misc-RE/2020-03-27-dridex-worker-config-software-banking-yara.vk.yar##" | \
    # Remove files with errors
    sed -E "s#sub/Malware-Misc-RE/2020-04-07-qbot-qsort-miniupnp-vk.yar##" | \
    sed -E "s#sub/Malware-Misc-RE/2020-03-19-netwalker-yara-config-yar-vk.yar##" | \
    # Added to signature-base
    sed -E "s#sub/GCTI/.*##" | \
    tr '\n' ' ' | \
    xargs -0 cat >> total/total.yara
    # sed -E "s###" | \
