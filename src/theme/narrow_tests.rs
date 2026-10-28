use super::*;

fn click(pos: egui::Pos2) -> Vec<egui::Event> {
    vec![
        egui::Event::PointerMoved(pos),
        egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed: true,
            modifiers: egui::Modifiers::NONE,
        },
        egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: egui::Modifiers::NONE,
        },
    ]
}

fn point(output: &egui::FullOutput, label: &str) -> egui::Pos2 {
    output
        .shapes
        .iter()
        .find_map(|shape| match &shape.shape {
            egui::Shape::Text(text) if text.galley.text() == label => {
                Some(text.galley.rect.translate(text.pos.to_vec2()).center())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {label}"))
}

fn frame(
    context: &egui::Context,
    width: f32,
    events: Vec<egui::Event>,
    draw: impl FnOnce(&mut Ui),
) -> egui::FullOutput {
    let time = context.input(|input| input.time) + 0.1;
    let mut draw = Some(draw);
    let mut output = context.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(width, 500.0),
            )),
            time: Some(time),
            events,
            ..Default::default()
        },
        |ui| draw.take().unwrap()(ui),
    );
    output.textures_delta.clear();
    output
}

fn context(scale: f32) -> egui::Context {
    let context = egui::Context::default();
    install(&context);
    context.set_pixels_per_point(scale);
    context.all_styles_mut(|style| style.animation_time = 0.0);
    context
}

#[test]
fn explicit_tab_overflow_reaches_each_hidden_view_at_fractional_widths() {
    let tabs = [
        (0, "Listing"),
        (1, "Function Graph"),
        (2, "Strings"),
        (3, "FindCrypt"),
        (4, "Decode"),
        (5, "Hex / Memory Map"),
        (6, "References"),
        (7, "Future search view"),
    ];
    for scale in [1.0, 1.25] {
        for width in [120.0, 180.0, 240.0, 315.0, 600.0] {
            let context = context(scale);
            let mut current = 0;
            let mut draw = |events| {
                frame(&context, width, events, |ui| {
                    dock_tabs(
                        ui,
                        &mut current,
                        &tabs,
                        Some(("Saved analysis", "Saved results")),
                        |_| {},
                    );
                })
            };
            draw(vec![]);
            for (_, label) in tabs {
                let output = draw(vec![]);
                assert_eq!(context.pixels_per_point(), scale);
                let more = point(&output, "»");
                draw(click(more));
                let output = draw(vec![]);
                // Already visible tabs are deliberately absent from the menu.
                let target = output
                    .shapes
                    .iter()
                    .filter_map(|shape| match &shape.shape {
                        egui::Shape::Text(text) if text.galley.text() == label => {
                            Some(text.galley.rect.translate(text.pos.to_vec2()).center())
                        }
                        _ => None,
                    })
                    .max_by(|a, b| a.y.total_cmp(&b.y))
                    .unwrap();
                draw(click(target));
                // Clicking an inline tab can leave the unrelated menu open.
                draw(vec![egui::Event::Key {
                    key: egui::Key::Escape,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                }]);
                let output = draw(vec![]);
                let active = point(&output, label);
                assert!(
                    active.y < 40.0,
                    "active tab stays on strip: {width}/{scale}/{label}"
                );
                let saved = output
                    .shapes
                    .iter()
                    .find_map(|shape| match &shape.shape {
                        egui::Shape::Text(text)
                            if ["Saved", "Saved analysis"].contains(&text.galley.text()) =>
                        {
                            Some(text.galley.rect.translate(text.pos.to_vec2()))
                        }
                        _ => None,
                    })
                    .unwrap();
                assert!(
                    saved.left() > active.x,
                    "provenance stays beside active tab"
                );
            }
        }
    }
}

#[test]
fn action_overflow_preserves_disabled_and_checked_state() {
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Action {
        Copy,
        Refresh,
        Auto,
        Signature,
    }
    for scale in [1.0, 1.25] {
        for width in [180.0, 700.0] {
            let context = context(scale);
            let mut automatic = true;
            let mut chosen = None;
            let mut dispatched = Vec::new();
            let mut draw = |events| {
                chosen = None;
                frame(&context, width, events, |ui| {
                    let actions = [
                        DockAction {
                            id: Action::Copy,
                            label: "Copy",
                            tooltip: "Copy full source",
                            enabled: true,
                            priority: 0,
                            kind: DockActionKind::Button,
                        },
                        DockAction {
                            id: Action::Refresh,
                            label: "Refresh",
                            tooltip: "Refresh",
                            enabled: true,
                            priority: 1,
                            kind: DockActionKind::Button,
                        },
                        DockAction {
                            id: Action::Auto,
                            label: "Auto",
                            tooltip: "Auto",
                            enabled: true,
                            priority: 2,
                            kind: DockActionKind::Toggle(automatic),
                        },
                        DockAction {
                            id: Action::Signature,
                            label: "Signature…",
                            tooltip: "No graph",
                            enabled: false,
                            priority: 3,
                            kind: DockActionKind::Button,
                        },
                    ];
                    chosen = dock_header_actions(
                        ui,
                        "Decompiler",
                        Some(("Saved analysis", "Saved source")),
                        &actions,
                    );
                    if let Some(action) = chosen {
                        dispatched.push(action);
                    }
                    if chosen == Some(Action::Auto) {
                        automatic = !automatic;
                    }
                })
            };
            draw(vec![]);
            let output = draw(vec![]);
            if width < 200.0 {
                draw(click(point(&output, "⋯")));
            }
            let output = draw(vec![]);
            draw(click(point(&output, "Signature…")));
            let output = draw(vec![]);
            if width < 200.0 && !output.shapes.iter().any(|shape| matches!(&shape.shape, egui::Shape::Text(text) if text.galley.text() == "Auto")) {
                draw(click(point(&output, "⋯")));
            }
            let output = draw(vec![]);
            draw(click(point(&output, "Auto")));
            // End mutable closure borrows before inspecting dispatched state.
            assert!(
                !automatic,
                "checkbox toggles through visible or overflow control"
            );
            assert_eq!(chosen, Some(Action::Auto));
            assert!(
                !dispatched.contains(&Action::Signature),
                "disabled actions do not dispatch"
            );
        }
    }
}

#[test]
fn empty_and_replaced_tabs_do_not_panic_or_keep_invalid_selection() {
    let context = context(1.25);
    let mut selected = 9;
    frame(&context, 120.0, vec![], |ui| {
        dock_tabs(ui, &mut selected, &[], None, |_| {});
    });
    frame(&context, 120.0, vec![], |ui| {
        assert!(dock_tabs(
            ui,
            &mut selected,
            &[(1, "First"), (2, "Second")],
            None,
            |_| {}
        ));
    });
    assert_eq!(selected, 1);
    frame(&context, 120.0, vec![], |ui| {
        assert!(dock_tabs(
            ui,
            &mut selected,
            &[(3, "Replacement")],
            None,
            |_| {}
        ));
    });
    assert_eq!(selected, 3);
}

#[test]
fn fractional_strips_are_stable_and_keep_paint_inside_the_strip() {
    for scale in [1.0, 1.25] {
        for width in [179.2, 180.0, 180.8, 315.0] {
            let context = context(scale);
            let mut selected = 1;
            let mut stable = None;
            for step in 0..20 {
                let output = frame(&context, width, vec![], |ui| {
                    dock_tabs(
                        ui,
                        &mut selected,
                        &[(0, "Functions"), (1, "Imports"), (2, "Exports")],
                        Some(("Saved analysis", "Saved functions")),
                        |ui| {
                            ui.weak("262144");
                        },
                    );
                });
                let geometry: Vec<_> = output
                    .shapes
                    .iter()
                    .filter_map(|shape| match &shape.shape {
                        egui::Shape::Text(text) => {
                            let bounds = text.galley.rect.translate(text.pos.to_vec2());
                            assert!(
                                bounds.right() <= shape.clip_rect.right() + 1.0 / scale,
                                "{width}/{scale}: {} {bounds:?} {:?}",
                                text.galley.text(),
                                shape.clip_rect
                            );
                            Some((text.galley.text().to_owned(), bounds))
                        }
                        _ => None,
                    })
                    .collect();
                if step >= 3 {
                    if let Some(previous) = &stable {
                        assert_eq!(&geometry, previous);
                    }
                    stable = Some(geometry);
                }
            }
        }
    }
}

#[test]
fn responsive_listing_paints_code_and_colors_inside_real_viewports() {
    for scale in [1.0, 1.25] {
        for width in [180.0, 260.0, 360.0, 800.0] {
            let context = context(scale);
            let output = frame(&context, width, vec![], |ui| {
                let glyph = glyph_width(ui);
                let (_, output) = rows::<()>(
                    ui,
                    "narrow-list",
                    1_000,
                    ROW_HEIGHT,
                    0.0,
                    None,
                    |ui, _, rect| {
                        let columns = listing_columns(rect.width(), glyph, 16, scale);
                        assert!(columns.mnemonic.span() > 0.0 && columns.operands.span() > 0.0);
                        listing_cells(
                            ui,
                            rect,
                            &columns,
                            &ListingRow {
                                address: 0x1234_5678_9abc_def0,
                                address_digits: 16,
                                bytes: &[0x66; 15],
                                mnemonic: "MOV",
                                operands: "rax, [rip + café_very_long_operand_with_more_content]",
                                callee: Some("Function"),
                                comment: Some("comment"),
                            },
                        );
                        None
                    },
                );
                assert_eq!(output.state.clamped_offset().x, 0.0);
                assert!(output.content_size.x <= output.inner_rect.width() + 1.0 / scale);
            });
            assert!(output.shapes.iter().any(|shape| matches!(&shape.shape, egui::Shape::Text(text) if text.galley.text() == "MOV" && text.galley.job.sections[0].format.color == MNEMONIC)));
            for shape in &output.shapes {
                if let egui::Shape::Text(text) = &shape.shape {
                    let bounds = text.galley.rect.translate(text.pos.to_vec2());
                    assert!(bounds.right() <= shape.clip_rect.right() + 1.0 / scale);
                    assert_eq!(text.galley.rows.len(), 1);
                }
            }
        }
    }
}

#[test]
fn replacing_overflowed_tabs_closes_the_obsolete_popup() {
    let context = context(1.25);
    let mut current = 1;
    let tabs = [(1, "A long active view"), (2, "Another hidden view")];
    let mut draw = |events| {
        frame(&context, 120.0, events, |ui| {
            dock_tabs(ui, &mut current, &tabs, None, |_| {});
        })
    };
    draw(vec![]);
    let output = draw(vec![]);
    draw(click(point(&output, "»")));
    assert!(egui::Popup::is_any_open(&context));
    frame(&context, 120.0, vec![], |ui| {
        dock_tabs(ui, &mut current, &[], None, |_| {});
    });
    assert!(!egui::Popup::is_any_open(&context));
}
