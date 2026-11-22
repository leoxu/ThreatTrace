from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .threat import ThreatRegistry


_PRIORITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def _capture_scene_png(scene, margin: int = 40) -> bytes:
    from PySide6.QtCore import QRectF
    from PySide6.QtGui import QImage, QPainter
    from PySide6.QtCore import Qt

    bounding = scene.itemsBoundingRect().adjusted(-margin, -margin, margin, margin)
    w = max(int(bounding.width() * 2), 1)
    h = max(int(bounding.height() * 2), 1)
    img = QImage(w, h, QImage.Format_ARGB32)
    img.fill(Qt.white)
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    scene.render(p, QRectF(0, 0, w, h), bounding)
    p.end()

    from PySide6.QtCore import QBuffer, QIODevice
    buf = QBuffer()
    buf.open(QIODevice.WriteOnly)
    img.save(buf, "PNG")
    return bytes(buf.data())


def _load_document_image(doc, name: str):
    """The image behind a document image fragment, resolved against its base URL."""
    from PySide6.QtCore import QUrl
    from PySide6.QtGui import QImage, QTextDocument

    url = QUrl(name)
    resolved = doc.baseUrl().resolved(url) if not url.isLocalFile() else url
    image = QImage(resolved.toLocalFile())
    if image.isNull():
        # Fall back to whatever the document holds for that resource.
        data = doc.resource(QTextDocument.ResourceType.ImageResource, url)
        image = QImage(data) if isinstance(data, QImage) else QImage()
    return image


def fit_document_images_to_page(doc, printer) -> None:
    """Scale every image in *doc* down so it fits the printer's printable area.

    QTextDocument.print_() lays the document out at 96 dpi and scales it to the
    printer's resolution (1200 dpi by default), so an image is placed at its
    pixel size × that factor — a 2000 px diagram becomes ~25000 device px wide
    and is clipped at the page edge. Setting an explicit width/height on the
    image format (in document units) makes it fit while the high-resolution
    source is still used for printing.
    """
    from PySide6.QtCore import QUrl
    from PySide6.QtGui import QTextCursor, QTextDocument

    page = printer.pageLayout().paintRectPixels(printer.resolution())
    scale = max(printer.resolution() / 96.0, 1e-6)   # document dpi -> device dpi
    max_w = page.width() / scale
    max_h = page.height() / scale
    if max_w <= 0 or max_h <= 0:
        return

    edits = []          # (position, length, QTextImageFormat) collected first
    block = doc.begin()
    while block.isValid():
        it = block.begin()
        while not it.atEnd():
            fragment = it.fragment()
            fmt = fragment.charFormat()
            if fragment.isValid() and fmt.isImageFormat():
                img_fmt = fmt.toImageFormat()
                image = _load_document_image(doc, img_fmt.name())
                if not image.isNull():
                    # Register it under the name the fragment uses: QTextDocument
                    # does not resolve a relative markdown image path on its own
                    # and would print a "broken image" placeholder instead.
                    doc.addResource(QTextDocument.ResourceType.ImageResource,
                                    QUrl(img_fmt.name()), image)
                w = img_fmt.width() or (image.width() if not image.isNull() else 0)
                h = img_fmt.height() or (image.height() if not image.isNull() else 0)
                if w > 0 and h > 0:
                    factor = min(max_w / w, max_h / h, 1.0)
                    if factor < 1.0:
                        img_fmt.setWidth(w * factor)
                        img_fmt.setHeight(h * factor)
                        edits.append((fragment.position(), fragment.length(), img_fmt))
            it += 1
        block = block.next()

    for position, length, img_fmt in edits:
        cursor = QTextCursor(doc)
        cursor.setPosition(position)
        cursor.setPosition(position + length, QTextCursor.KeepAnchor)
        cursor.mergeCharFormat(img_fmt)


def _group_threats_by_boundary(scene, threats: "ThreatRegistry") -> Dict[str, list]:
    from .graphics.items import EdgeItem, NodeItem

    edge_to_boundary: Dict[str, str] = {}
    for item in scene.items():
        if isinstance(item, EdgeItem) and item.src and item.dst:
            dst_node = item.dst.parentItem()
            src_node = item.src.parentItem()
            boundary = None
            if isinstance(dst_node, NodeItem):
                boundary = dst_node.boundary
            if boundary is None and isinstance(src_node, NodeItem):
                boundary = src_node.boundary
            boundary_name = (
                str(boundary.properties().get("name", "Unknown Boundary"))
                if boundary else "No Boundary"
            )
            edge_to_boundary[item.edge_id] = boundary_name

    grouped: Dict[str, list] = {}
    for t in threats.values():
        boundary_name = edge_to_boundary.get(t.edge_guid, "No Boundary")
        grouped.setdefault(boundary_name, []).append(t)

    for group in grouped.values():
        group.sort(key=lambda t: (_PRIORITY_ORDER.get(t.priority, 3), t.title))
    return grouped


def _build_threat_table(threat_list: list) -> str:
    lines = [
        "| # | Title | Category | Priority | CVSS | Status | Mitigated |",
        "|---|-------|----------|----------|------|--------|-----------|",
    ]
    for i, t in enumerate(threat_list, 1):
        cvss = "—"
        if all([t.cvss_av, t.cvss_ac, t.cvss_pr, t.cvss_ui,
                t.cvss_s, t.cvss_c, t.cvss_i, t.cvss_a]):
            from .cvss import cvss_base_score
            cvss = f"{cvss_base_score(t.cvss_av, t.cvss_ac, t.cvss_pr, t.cvss_ui, t.cvss_s, t.cvss_c, t.cvss_i, t.cvss_a):.1f}"
        mitigated = "Yes" if t.mitigation_sc_ids else "No"
        title = t.title.replace("|", "\\|") or "—"
        cat = (t.category or "—").replace("|", "\\|")
        lines.append(
            f"| {i} | {title} | {cat} | {t.priority or '—'} | {cvss} | {t.status or '—'} | {mitigated} |"
        )
    return "\n".join(lines) + "\n\n"


def export_markdown(scene, threats: "ThreatRegistry", diag_name: str, out_path: Path) -> None:
    from .ui.attack_surface_panel import scan_attack_surface

    png_bytes = _capture_scene_png(scene)
    png_path = out_path.with_suffix(".png")
    png_path.write_bytes(png_bytes)

    date_str = datetime.now().strftime("%Y-%m-%d")
    lines: List[str] = [
        f"# Threat Model: {diag_name}\n\n",
        f"Generated: {date_str}\n\n",
        f"![Diagram]({png_path.name})\n\n",
    ]

    total = len(threats)
    mitigated = sum(1 for t in threats.values() if t.mitigation_sc_ids)
    lines.append(f"**Threats:** {total} total, {mitigated} mitigated, {total - mitigated} open\n\n")

    grouped = _group_threats_by_boundary(scene, threats)
    if grouped:
        lines.append("---\n\n## Threats by Boundary\n\n")
        for boundary_name in sorted(grouped):
            threat_list = grouped[boundary_name]
            lines.append(f"### {boundary_name}\n\n")
            lines.append(_build_threat_table(threat_list))

    entry_points = scan_attack_surface(scene, threats)
    if entry_points:
        lines.append("---\n\n## Attack Surface Entry Points\n\n")
        lines.append("| Edge | Source | Destination | Boundary | Threats | Open |\n")
        lines.append("|------|--------|-------------|----------|---------|------|\n")
        for ep in entry_points:
            lines.append(
                f"| {ep.edge_label} | {ep.src_name} | {ep.dst_name} "
                f"| {ep.boundary_name} | {ep.threat_count} | {ep.unmitigated} |\n"
            )
        lines.append("\n")

    out_path.write_text("".join(lines), encoding="utf-8")


def export_pdf(scene, threats: "ThreatRegistry", diag_name: str, out_path: Path) -> None:
    from PySide6.QtCore import QUrl
    from PySide6.QtPrintSupport import QPrinter
    from PySide6.QtGui import QTextDocument

    md_path = out_path.with_suffix(".md")
    export_markdown(scene, threats, diag_name, md_path)

    printer = QPrinter(QPrinter.HighResolution)
    printer.setOutputFormat(QPrinter.PdfFormat)
    printer.setOutputFileName(str(out_path))
    doc = QTextDocument()
    # Resolve the ![](diagram.png) link relative to the markdown file.
    doc.setBaseUrl(QUrl.fromLocalFile(str(md_path.parent) + "/"))
    doc.setMarkdown(md_path.read_text(encoding="utf-8"))
    fit_document_images_to_page(doc, printer)
    doc.print_(printer)
