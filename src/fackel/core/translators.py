from __future__ import annotations

from typing import Any, Iterable

from fackel.core.tracking import (
    InfoRecord,
    InfoType,
    RawToolEvent,
    Translator,
    fingerprint,
    normalize_value,
)


class HttpxTranslator:
    def accepts(self, raw: RawToolEvent) -> bool:
        return raw.tool == "httpx_scan" and raw.payload.get("status") == "ok"

    def translate(self, raw: RawToolEvent) -> Iterable[InfoRecord]:
        results = raw.payload.get("results") or []
        for entry in results:
            url = entry.get("url")
            ip = entry.get("ip")
            port = entry.get("port")
            if url:
                norm = normalize_value(InfoType.URL, url)
                fp = fingerprint(InfoType.URL, norm)
                yield InfoRecord(
                    info_type=InfoType.URL,
                    value=norm,
                    fingerprint=fp,
                    source_tool=raw.tool,
                    first_seen=raw.observed_at,
                    last_seen=raw.observed_at,
                    state="active",
                )
            if ip and port:
                svc_val = f"{ip}:{port}/tcp"
                fp_svc = fingerprint(InfoType.SERVICE, svc_val)
                yield InfoRecord(
                    info_type=InfoType.SERVICE,
                    value=svc_val,
                    fingerprint=fp_svc,
                    source_tool=raw.tool,
                    first_seen=raw.observed_at,
                    last_seen=raw.observed_at,
                    state="active",
                )


class NaabuTranslator:
    def accepts(self, raw: RawToolEvent) -> bool:
        return raw.tool == "naabu_scan" and raw.payload.get("status") == "ok"

    def translate(self, raw: RawToolEvent) -> Iterable[InfoRecord]:
        for entry in raw.payload.get("results", []) or []:
            ip = entry.get("ip")
            port = entry.get("port")
            proto = entry.get("proto") or "tcp"
            if not (ip and port):
                continue
            svc_val = f"{ip}:{port}/{proto}"
            fp_svc = fingerprint(InfoType.SERVICE, svc_val)
            yield InfoRecord(
                info_type=InfoType.SERVICE,
                value=svc_val,
                fingerprint=fp_svc,
                source_tool=raw.tool,
                first_seen=raw.observed_at,
                last_seen=raw.observed_at,
                state="active",
            )


class ProbeHostTranslator:
    def accepts(self, raw: RawToolEvent) -> bool:
        return raw.tool == "probe_host" and raw.payload.get("status") == "ok"

    def translate(self, raw: RawToolEvent) -> Iterable[InfoRecord]:
        ip = raw.payload.get("ip")
        host = raw.payload.get("host")
        if ip:
            norm_ip = normalize_value(InfoType.IP, ip)
            fp_ip = fingerprint(InfoType.IP, norm_ip)
            yield InfoRecord(
                info_type=InfoType.IP,
                value=norm_ip,
                fingerprint=fp_ip,
                source_tool=raw.tool,
                first_seen=raw.observed_at,
                last_seen=raw.observed_at,
                state="active",
            )
        for svc in raw.payload.get("services", []) or []:
            scheme = svc.get("scheme")
            port = svc.get("port")
            if host and scheme and port:
                url_val = f"{scheme}://{host}"
                fp_url = fingerprint(InfoType.URL, url_val)
                yield InfoRecord(
                    info_type=InfoType.URL,
                    value=normalize_value(InfoType.URL, url_val),
                    fingerprint=fp_url,
                    source_tool=raw.tool,
                    first_seen=raw.observed_at,
                    last_seen=raw.observed_at,
                    state="active",
                )
                svc_val = f"{ip or host}:{port}/{scheme}"
                fp_svc = fingerprint(InfoType.SERVICE, svc_val)
                yield InfoRecord(
                    info_type=InfoType.SERVICE,
                    value=svc_val,
                    fingerprint=fp_svc,
                    source_tool=raw.tool,
                    first_seen=raw.observed_at,
                    last_seen=raw.observed_at,
                    state="active",
                )


class NmapTranslator:
    def accepts(self, raw: RawToolEvent) -> bool:
        return raw.tool == "nmap_port_scan" and raw.payload.get("status") == "ok"

    def translate(self, raw: RawToolEvent) -> Iterable[InfoRecord]:
        host = raw.payload.get("host")
        for svc in raw.payload.get("services", []) or []:
            port = svc.get("port")
            proto = svc.get("protocol") or "tcp"
            if port:
                svc_val = f"{host}:{port}/{proto}"
                fp_svc = fingerprint(InfoType.SERVICE, svc_val)
                yield InfoRecord(
                    info_type=InfoType.SERVICE,
                    value=svc_val,
                    fingerprint=fp_svc,
                    source_tool=raw.tool,
                    first_seen=raw.observed_at,
                    last_seen=raw.observed_at,
                    state="active",
                )
            for cve in svc.get("cves", []) or []:
                vul_val = f"{cve.get('id')}@{host}:{port}"
                fp_vul = fingerprint(InfoType.VULNERABILITY, vul_val)
                yield InfoRecord(
                    info_type=InfoType.VULNERABILITY,
                    value=vul_val,
                    fingerprint=fp_vul,
                    source_tool=raw.tool,
                    first_seen=raw.observed_at,
                    last_seen=raw.observed_at,
                    state="active",
                )


class NucleiTranslator:
    def accepts(self, raw: RawToolEvent) -> bool:
        return raw.tool == "nuclei_scan" and raw.payload.get("status") == "ok"

    def translate(self, raw: RawToolEvent) -> Iterable[InfoRecord]:
        for finding in raw.payload.get("findings", []) or []:
            tpl = finding.get("template_id")
            matched = (
                finding.get("matched")
                or finding.get("host")
                or raw.payload.get("target")
            )
            if tpl and matched:
                val = f"{tpl}:{matched}"
                fp_vul = fingerprint(InfoType.VULNERABILITY, val)
                yield InfoRecord(
                    info_type=InfoType.VULNERABILITY,
                    value=val,
                    fingerprint=fp_vul,
                    source_tool=raw.tool,
                    first_seen=raw.observed_at,
                    last_seen=raw.observed_at,
                    state="active",
                )


class KatanaTranslator:
    def accepts(self, raw: RawToolEvent) -> bool:
        return raw.tool == "katana_crawl" and raw.payload.get("status") == "ok"

    def translate(self, raw: RawToolEvent) -> Iterable[InfoRecord]:
        for url in raw.payload.get("urls", []) or []:
            norm = normalize_value(InfoType.URL, url)
            fp_url = fingerprint(InfoType.URL, norm)
            yield InfoRecord(
                info_type=InfoType.URL,
                value=norm,
                fingerprint=fp_url,
                source_tool=raw.tool,
                first_seen=raw.observed_at,
                last_seen=raw.observed_at,
                state="active",
            )


class FeroxbusterTranslator:
    def accepts(self, raw: RawToolEvent) -> bool:
        return raw.tool == "feroxbuster_scan" and raw.payload.get("status") == "ok"

    def translate(self, raw: RawToolEvent) -> Iterable[InfoRecord]:
        for entry in raw.payload.get("results", []) or []:
            url = entry.get("url")
            if url:
                norm = normalize_value(InfoType.URL, url)
                fp_url = fingerprint(InfoType.URL, norm)
                yield InfoRecord(
                    info_type=InfoType.URL,
                    value=norm,
                    fingerprint=fp_url,
                    source_tool=raw.tool,
                    first_seen=raw.observed_at,
                    last_seen=raw.observed_at,
                    state="active",
                )


class Wafw00fTranslator:
    def accepts(self, raw: RawToolEvent) -> bool:
        return raw.tool == "wafw00f_detect" and raw.payload.get("status") == "ok"

    def translate(self, raw: RawToolEvent) -> Iterable[InfoRecord]:
        target = raw.payload.get("target") or ""
        waf = raw.payload.get("waf_name") or "unknown"
        if waf:
            val = f"waf:{waf}@{target}"
            fp = fingerprint(InfoType.OTHER, val)
            yield InfoRecord(
                info_type=InfoType.OTHER,
                value=val,
                fingerprint=fp,
                source_tool=raw.tool,
                first_seen=raw.observed_at,
                last_seen=raw.observed_at,
                state="active",
            )


DEFAULT_TRANSLATORS: list[Translator] = [
    HttpxTranslator(),
    NaabuTranslator(),
    ProbeHostTranslator(),
    NmapTranslator(),
    NucleiTranslator(),
    KatanaTranslator(),
    FeroxbusterTranslator(),
    Wafw00fTranslator(),
]
