//! Secret engine list renderer.
//!
//! Every mount is listed, but only KV2 engines can be browsed with the KV2
//! endpoints this app speaks. The renderer therefore shows each mount's type
//! and dims the ones that are not KV2, plus a detail block for the selected
//! engine (type, version, accessor, lease TTLs, description).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::row::SELECTION_MARKER;
use crate::constants::{NA_VALUE, titles};
use crate::model::EngineInfo;
use crate::theme::Theme;

/// Height of the engine detail block (borders plus four detail rows).
const DETAIL_HEIGHT: u16 = 6;

/// Data rendered by the secret engine list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnginesModel {
    /// Available secret engines.
    pub engines: Vec<EngineInfo>,
    /// Selected engine index.
    pub selected: usize,
}

/// Render the secret engine list with a detail block for the selected engine.
pub fn draw_engines(frame: &mut Frame<'_>, area: Rect, model: &EnginesModel, theme: &Theme) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            titles::ENGINES,
            Style::default().fg(theme.title),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let selected = selected_index(model.selected, model.engines.len());
    let detail_engine = selected.and_then(|index| model.engines.get(index));
    // The detail block only appears when there is a selection and room for it;
    // short terminals keep the list only.
    let detail_area = if detail_engine.is_some() && inner.height > DETAIL_HEIGHT {
        let rows =
            Layout::vertical([Constraint::Min(1), Constraint::Length(DETAIL_HEIGHT)]).split(inner);
        match rows.as_ref() {
            [_, detail] => Some(*detail),
            _ => None,
        }
    } else {
        None
    };
    let list_area = detail_area.map_or(inner, |detail| Rect {
        height: detail.y.saturating_sub(inner.y),
        ..inner
    });

    render_list(frame, list_area, model, selected, theme);
    if let (Some(area), Some(engine)) = (detail_area, detail_engine) {
        draw_detail(frame, area, engine, theme);
    }
}

fn render_list(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &EnginesModel,
    selected: Option<usize>,
    theme: &Theme,
) {
    if area.height == 0 {
        return;
    }
    let visible_rows = usize::from(area.height);
    // Window the list around the selection: the detail block shrinks the list
    // area, so a plain `take(visible_rows)` can leave the highlighted mount
    // off-screen (Enter would still act on it). Rows keep their absolute index
    // so the selection marker stays correct.
    let first_row = selected.map_or(0, |selected| {
        selected.saturating_sub(visible_rows.saturating_sub(1))
    });
    let lines: Vec<Line<'_>> = model
        .engines
        .iter()
        .skip(first_row)
        .take(visible_rows)
        .enumerate()
        .map(|(offset, engine)| {
            engine_line(first_row + offset, selected, engine, theme, area.width)
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

/// One engine row: `▌ name` padded to the row width, with the type label flush
/// right. Non-KV2 engines are dimmed and their type label carries the warning
/// color so an unbrowsable mount is obvious before pressing Enter.
fn engine_line(
    index: usize,
    selected: Option<usize>,
    engine: &EngineInfo,
    theme: &Theme,
    width: u16,
) -> Line<'static> {
    let is_selected = selected == Some(index);
    let marker = if is_selected {
        format!("{SELECTION_MARKER} ")
    } else {
        "  ".to_owned()
    };
    let type_col = format!(" {}", engine.type_label());
    let name_width = usize::from(width).saturating_sub(2 + type_col.chars().count());
    let name_pad = format!(
        "{:<width$}",
        truncate_label(engine.name.as_str(), name_width),
        width = name_width
    );

    if is_selected {
        let style = Style::default()
            .bg(theme.selected_bg)
            .fg(theme.selected_fg)
            .add_modifier(Modifier::BOLD);
        return Line::from(vec![
            Span::styled(marker, style),
            Span::styled(name_pad, style),
            Span::styled(type_col, style),
        ]);
    }
    let (name_fg, type_fg) = if engine.supports_browsing() {
        (theme.leaf_fg, theme.masked_fg)
    } else {
        (theme.masked_fg, theme.status_warn)
    };
    Line::from(vec![
        Span::raw(marker),
        Span::styled(name_pad, Style::default().fg(name_fg)),
        Span::styled(type_col, Style::default().fg(type_fg)),
    ])
}

/// Detail block for the selected engine.
fn draw_detail(frame: &mut Frame<'_>, area: Rect, engine: &EngineInfo, theme: &Theme) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            format!(" {} ", engine.name.as_str()),
            Style::default().fg(theme.title),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let width = usize::from(inner.width);
    // An unreported version is a KV1 mount; show `n/a` rather than inventing one.
    let version = engine
        .kv_version
        .map_or_else(|| NA_VALUE.to_owned(), |version| version.to_string());
    let description = if engine.description.is_empty() {
        NA_VALUE
    } else {
        engine.description.as_str()
    };
    let (hint, hint_fg) = if engine.supports_browsing() {
        (
            "browse: press Enter to open secrets".to_owned(),
            theme.masked_fg,
        )
    } else if engine.is_kv1() {
        (
            "browsing unsupported: KV v1 mounts cannot be browsed".to_owned(),
            theme.status_warn,
        )
    } else {
        (
            "browsing unsupported: only KV2 engines can be browsed".to_owned(),
            theme.status_warn,
        )
    };
    let lines = vec![
        detail_line(
            &format!(
                "type: {} | version: {} | accessor: {}",
                engine.type_label(),
                version,
                engine.accessor
            ),
            width,
            theme.leaf_fg,
        ),
        detail_line(
            &format!(
                "lease ttl: default {}s | max {}s",
                engine.default_lease_ttl, engine.max_lease_ttl
            ),
            width,
            theme.leaf_fg,
        ),
        detail_line(&format!("description: {description}"), width, theme.leaf_fg),
        detail_line(&hint, width, hint_fg),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

fn detail_line(text: &str, width: usize, fg: Color) -> Line<'static> {
    Line::from(Span::styled(
        truncate_label(text, width),
        Style::default().fg(fg),
    ))
}

fn truncate_label(label: &str, max: usize) -> String {
    if label.chars().count() <= max {
        return label.to_owned();
    }
    label.chars().take(max).collect()
}

fn selected_index(selected: usize, len: usize) -> Option<usize> {
    len.checked_sub(1).map(|last| selected.min(last))
}

#[cfg(test)]
mod tests {
    use insta::assert_snapshot;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::layout::Rect;

    use super::*;
    use crate::path::SecretPath;

    fn render(width: u16, height: u16, draw: impl FnOnce(&mut ratatui::Frame<'_>)) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("TestBackend");
        terminal.draw(draw).expect("draw");
        let buffer = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(
                    buffer
                        .cell((x, y))
                        .map_or("", ratatui::buffer::Cell::symbol),
                );
            }
            out.push('\n');
        }
        out
    }

    fn engine(name: &str, mount_type: &str, version: Option<u64>) -> EngineInfo {
        EngineInfo {
            name: SecretPath::new(name),
            mount_type: mount_type.to_owned(),
            kv_version: version,
            accessor: format!("{mount_type}_accessor"),
            description: String::new(),
            default_lease_ttl: 0,
            max_lease_ttl: 0,
        }
    }

    fn engines() -> Vec<EngineInfo> {
        vec![
            engine("secret", "kv", Some(2)),
            engine("kv", "kv", Some(2)),
            engine("team", "kv", Some(2)),
            engine("infra", "kv", Some(2)),
            engine("apps", "kv", Some(2)),
        ]
    }

    #[test]
    fn engines_selects_first_row() {
        let model = EnginesModel {
            engines: engines(),
            selected: 0,
        };
        assert_snapshot!(
            "engines_selected_first",
            render(32, 8, |f| draw_engines(
                f,
                Rect::new(0, 0, 32, 8),
                &model,
                &Theme::default()
            ))
        );
    }

    #[test]
    fn engines_clamps_selection_to_last_row() {
        let model = EnginesModel {
            engines: engines(),
            selected: 30,
        };
        assert_snapshot!(
            "engines_selection_clamped",
            render(32, 8, |f| draw_engines(
                f,
                Rect::new(0, 0, 32, 8),
                &model,
                &Theme::default()
            ))
        );
    }

    #[test]
    fn engines_empty_list() {
        let model = EnginesModel {
            engines: Vec::new(),
            selected: 0,
        };
        assert_snapshot!(
            "engines_empty",
            render(32, 5, |f| draw_engines(
                f,
                Rect::new(0, 0, 32, 5),
                &model,
                &Theme::default()
            ))
        );
    }

    #[test]
    fn engines_marks_non_kv2_and_shows_kv2_detail() {
        // Given: a KV2 mount selected among unsupported engines.
        let mut kv2 = engine("secret", "kv", Some(2));
        kv2.description = "app secrets".to_owned();
        let mut cubbyhole = engine("cubbyhole", "cubbyhole", None);
        cubbyhole.description = "per-token storage".to_owned();
        let model = EnginesModel {
            engines: vec![cubbyhole, engine("legacy", "kv", Some(1)), kv2],
            selected: 2,
        };
        // When/Then: the row shows `kv v2` and the detail block lists the metadata.
        assert_snapshot!(
            "engines_detail_kv2_selected",
            render(60, 12, |f| draw_engines(
                f,
                Rect::new(0, 0, 60, 12),
                &model,
                &Theme::default()
            ))
        );
    }

    #[test]
    fn engines_detail_for_unsupported_engine_says_so() {
        // Given: a cubbyhole mount selected.
        let model = EnginesModel {
            engines: vec![engine("cubbyhole", "cubbyhole", None)],
            selected: 0,
        };
        // When/Then: the detail block explains that browsing is unsupported.
        assert_snapshot!(
            "engines_detail_unsupported_selected",
            render(60, 12, |f| draw_engines(
                f,
                Rect::new(0, 0, 60, 12),
                &model,
                &Theme::default()
            ))
        );
    }

    #[test]
    fn engines_detail_for_unversioned_kv_mount_is_unsupported() {
        // Given: a `kv` mount reporting no version — the shape `vault secrets
        // enable kv` (without `-version`) produces, which is KV1.
        let model = EnginesModel {
            engines: vec![engine("legacykv", "kv", None)],
            selected: 0,
        };
        // When/Then: it is labelled KV v1 with no version, and not browsable.
        assert_snapshot!(
            "engines_detail_unversioned_kv_selected",
            render(60, 12, |f| draw_engines(
                f,
                Rect::new(0, 0, 60, 12),
                &model,
                &Theme::default()
            ))
        );
    }

    #[test]
    fn engines_keeps_selected_row_visible_when_detail_block_shrinks_the_list() {
        // Given: six engines and a 9-row inner area, which the detail block
        // reduces to a 3-row list; the last engine is selected.
        let model = EnginesModel {
            engines: (0..6)
                .map(|i| engine(&format!("e{i}"), "kv", Some(2)))
                .collect(),
            selected: 5,
        };

        // When: the view is rendered.
        let out = render(40, 11, |f| {
            draw_engines(f, Rect::new(0, 0, 40, 11), &model, &Theme::default());
        });

        // Then: the list scrolls so the selected row stays on screen with its
        // marker, and the off-window first rows are not drawn.
        assert!(out.contains(&format!("{SELECTION_MARKER} e5")));
        assert!(!out.contains("e0"));
    }
}
