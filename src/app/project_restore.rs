//! Where a reopened project lands. The project stores the exact selected
//! address; only an entry the resolver proves opens a function, so an
//! undecoded byte saved inside an executable section never becomes a
//! guessed function on reopen.

use eframe::egui;

use super::{DesktopApp, file_backed, graph_preparation, start_address};
use crate::model::{CodeMapping, FunctionView, function_at};
use crate::search_jobs::Destination;
use crate::semantic::SemanticInfo;

/// The saved function results a project restore may display.
pub(super) struct SavedResults {
    pub view: Option<FunctionView>,
    pub decompiled: Option<String>,
    pub mappings: Vec<CodeMapping>,
    pub semantics: SemanticInfo,
}

impl DesktopApp {
    /// Reopens the saved selection. Only an entry the resolver proves (an
    /// inventory entry, or an instruction of the saved view) opens a
    /// function; any other saved address lands on its exact Program row
    /// over the saved view, else over the saved displayed entry while it is
    /// still in the inventory, else over the opening address. Function scope
    /// opens the same function without landing.
    pub(super) fn restore_place(
        &mut self,
        saved: Option<u64>,
        displayed_entry: Option<u64>,
        results: SavedResults,
        cache_compatible: bool,
        context: &egui::Context,
    ) {
        let Some(info) = self.info.as_ref() else {
            return;
        };
        let saved = saved.filter(|&address| file_backed(info, address));
        let SavedResults {
            view,
            decompiled,
            mappings,
            semantics,
        } = results;
        let holds = |view: &FunctionView, pc: u64| {
            pc == view.address
                || mappings
                    .iter()
                    .any(|mapping| mapping.addresses.contains(&pc))
                || view
                    .blocks
                    .iter()
                    .any(|b| b.instructions.iter().any(|i| i.address == pc))
        };
        let proved = saved.and_then(|address| {
            match crate::search_jobs::resolve(info, address, 1, |pc| {
                view.as_ref()
                    .filter(|view| holds(view, pc))
                    .map(|view| view.address)
            }) {
                Some(Destination::Code { owner, .. }) => Some(owner),
                _ => None,
            }
        });
        let program = self.program_scope();
        if let Some(view) = view {
            let held = saved.is_none_or(|address| holds(&view, address));
            let address = view.address;
            let binding = self
                .results
                .binding(address, self.local_override_state(address));
            // The graph-dependent remainder runs once its geometry is ready,
            // never paired with another graph.
            let restore = graph_preparation::SavedRestore {
                generation: self.generation,
                selection: self.selection_generation,
                binding,
                selected: if held {
                    saved.or(Some(address))
                } else {
                    Some(address)
                },
                listing: saved.filter(|_| program && !held),
                decompiled,
                mappings,
                semantics,
            };
            let held = restore.retained_bytes();
            self.saved_result_revision = self.result_revision;
            self.prepare_graph(
                view,
                graph_preparation::Continuation::Saved(Box::new(restore)),
                held,
                context,
            );
            return;
        }
        let entry = proved
            .or_else(|| {
                displayed_entry.filter(|&entry| {
                    function_at(&info.functions, entry).is_some()
                        && crate::call_analysis::code_address(info, entry)
                })
            })
            .or_else(|| start_address(info));
        if let Some(entry) = entry {
            self.navigate(entry, true, context);
            self.status = if cache_compatible {
                "Project opened; loading function"
            } else {
                "Project opened; engine version changed, regenerating analysis"
            }
            .into();
        }
        if let Some(address) = saved.filter(|&address| program && Some(address) != entry) {
            self.land_in_listing(address, 1, None, false, context);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Instant;

    use super::super::program_listing::ListingScope;
    use super::super::tests as fixture;
    use super::super::{Pending, ProjectOpen, Tab};
    use super::*;
    use crate::linkage_ui::Place;
    use crate::model::{BasicBlock, Instruction, Request, Response, SectionInfo};
    use crate::program_listing::{Rank, Row};
    use crate::project::{LoadedProject, ProjectData};

    fn view(entry: u64, count: u64) -> FunctionView {
        FunctionView {
            address: entry,
            blocks: vec![BasicBlock {
                address: entry,
                instructions: (0..count)
                    .map(|i| Instruction {
                        address: entry + i * 4,
                        bytes: vec![0x90; 4],
                        mnemonic: "nop".into(),
                        operands: String::new(),
                    })
                    .collect(),
            }],
            edges: vec![],
            calls: vec![],
            warnings: vec![],
        }
    }

    /// A freshly opened binary: `.text` 0x1000–0x1100 with entries 0x1000
    /// and 0x1040, file-backed `.data` at 0x2000 and zero-filled `.bss` at
    /// 0x3000. Function requests queue rather than vanish without a worker.
    fn opened(scope: ListingScope) -> DesktopApp {
        let mut app = fixture::keyboard_app();
        let info = app.info.as_mut().unwrap();
        info.sections.push(SectionInfo {
            name: ".data".into(),
            address: 0x2000,
            size: 0x40,
            file_offset: 0x100,
            file_size: 0x40,
            executable: false,
        });
        info.sections.push(SectionInfo {
            name: ".bss".into(),
            address: 0x3000,
            size: 0x40,
            file_offset: 0x140,
            file_size: 0,
            executable: false,
        });
        info.file_len = 0x140;
        app.selected = None;
        app.address.clear();
        app.history.clear();
        app.set_listing_scope(scope);
        app.discovery_job = Some(mpsc::sync_channel(1).1);
        app
    }

    /// A project saved at `selected`, with the saved `view` (a compatible
    /// cache) or only the entry it displayed (an incompatible one).
    fn project(
        app: &DesktopApp,
        view: Option<FunctionView>,
        selected: Option<u64>,
        displayed_entry: Option<u64>,
    ) -> ProjectOpen {
        let data = ProjectData {
            function_results: Vec::new(),
            info: app.info.clone().unwrap(),
            session: app.session.clone().unwrap(),
            view,
            decompiled: None,
            mappings: Vec::new(),
            semantics: Default::default(),
            strings: Vec::new(),
            strings_truncated: false,
            crypto: Vec::new(),
            crypto_truncated: false,
            selected_address: selected,
            discovery: None,
        };
        ProjectOpen {
            function_results: Vec::new(),
            project: LoadedProject {
                cache_compatible: data.view.is_some(),
                data,
                binary: None,
                source_hint: "fixture".into(),
                displayed_entry,
            },
            project_path: "analysis.grproj".into(),
            binary_path: "fixture".into(),
            discovery_index: None,
        }
    }

    fn restore(app: &mut DesktopApp, project: ProjectOpen) {
        app.restore_project(project, &egui::Context::default());
        app.settle_graph();
    }

    /// The worker's graph for the function being opened, as a reply would
    /// deliver it, then one Listing frame.
    fn deliver_graph(app: &mut DesktopApp, view: FunctionView) {
        let context = egui::Context::default();
        let address = view.address;
        app.queue
            .retain(|request| !matches!(request, Request::Graph { address: a } if *a == address));
        let pending = Pending {
            id: 1,
            request: Request::Graph { address },
            started: Instant::now(),
            selection: app.selection_generation,
            revision: app.revision,
            byte_origin: (app.selected, app.tab),
            bytes: None,
            result: None,
        };
        app.receive(pending, Response::Graph { view }, &context);
        app.settle_graph();
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.main_panel(ui));
        output.textures_delta.clear();
    }

    fn graph_requested(app: &DesktopApp, address: u64) -> bool {
        app.queue
            .iter()
            .any(|request| matches!(request, Request::Graph { address: a } if *a == address))
    }

    fn graph_requested_any(app: &DesktopApp) -> bool {
        app.queue
            .iter()
            .any(|request| matches!(request, Request::Graph { .. }))
    }

    fn cursor(app: &DesktopApp) -> Option<Row> {
        let layout = app.program_layout()?;
        app.program_cursor(&layout)
    }

    #[test]
    fn an_undecoded_code_byte_reopens_on_its_row_never_as_a_guessed_function() {
        // A compatible cache: the saved view stays displayed.
        let mut app = opened(ListingScope::Program);
        let saved = project(&app, Some(view(0x1000, 4)), Some(0x1020), Some(0x1000));
        restore(&mut app, saved);
        assert_eq!(app.view().map(|view| view.address), Some(0x1000));
        assert_eq!(app.result_scope, Some(0x1000));
        assert!(!graph_requested(&app, 0x1020), "no guessed function");
        assert_eq!((app.selected, app.tab), (Some(0x1020), Tab::Listing));
        assert_eq!(cursor(&app), Some(Row::Byte { address: 0x1020 }));
        assert!(
            app.pending_listing_scroll.is_none(),
            "the row wins the scroll"
        );
        assert_eq!(app.history, [Place::Code(0x1000)]);
        assert_eq!(
            app.current_place(),
            Some(Place::Listing {
                address: 0x1020,
                rank: Rank::Body
            })
        );

        // An incompatible cache: the displayed entry opens, and the cursor
        // lands on the byte once that function's body arrives.
        let mut app = opened(ListingScope::Program);
        let saved = project(&app, None, Some(0x1020), Some(0x1000));
        restore(&mut app, saved);
        assert_eq!(app.result_scope, Some(0x1000));
        assert!(graph_requested(&app, 0x1000) && !graph_requested(&app, 0x1020));
        assert_eq!((app.selected, app.tab), (Some(0x1020), Tab::Listing));
        deliver_graph(&mut app, view(0x1000, 4));
        assert_eq!(app.view().map(|view| view.address), Some(0x1000));
        assert_eq!(app.selected, Some(0x1020));
        assert_eq!(cursor(&app), Some(Row::Byte { address: 0x1020 }));
        assert_eq!(app.history, [Place::Code(0x1000)]);
    }

    #[test]
    fn a_proved_instruction_reopens_its_owning_function() {
        for scope in [ListingScope::Program, ListingScope::Function] {
            // Held by the saved view.
            let mut app = opened(scope);
            let saved = project(&app, Some(view(0x1000, 4)), Some(0x1008), Some(0x1000));
            restore(&mut app, saved);
            assert_eq!(app.view().map(|view| view.address), Some(0x1000));
            assert_eq!(app.selected, Some(0x1008), "{scope:?}");
            assert!(!graph_requested_any(&app), "{scope:?}: {:?}", app.queue);
            // An inventory entry other than the displayed one, without a view.
            let mut app = opened(scope);
            let saved = project(&app, None, Some(0x1040), Some(0x1000));
            restore(&mut app, saved);
            assert_eq!(app.result_scope, Some(0x1040), "{scope:?}");
            assert_eq!(app.selected, Some(0x1040));
            assert!(graph_requested(&app, 0x1040) && !graph_requested(&app, 0x1000));
        }
        // Without its view an instruction is not proved: its displayed entry
        // opens, and the cursor lands on the instruction once decoded.
        let mut app = opened(ListingScope::Program);
        let saved = project(&app, None, Some(0x1008), Some(0x1000));
        restore(&mut app, saved);
        assert!(!graph_requested(&app, 0x1008));
        deliver_graph(&mut app, view(0x1000, 4));
        assert_eq!(app.selected, Some(0x1008));
        assert_eq!(
            cursor(&app),
            Some(Row::Instruction {
                owner: 0x1000,
                start: 0x1008,
                end: 0x100c
            })
        );
    }

    #[test]
    fn a_stale_displayed_entry_falls_back_to_the_opening_address() {
        for scope in [ListingScope::Program, ListingScope::Function] {
            for saved in [Some(0x1020), None] {
                let mut app = opened(scope);
                // 0x1060 is no longer an inventory entry.
                let project = project(&app, None, saved, Some(0x1060));
                restore(&mut app, project);
                assert_eq!(app.result_scope, Some(0x1000), "{scope:?} {saved:?}");
                assert!(graph_requested(&app, 0x1000));
                assert!(!graph_requested(&app, 0x1060) && !graph_requested(&app, 0x1020));
                let program = scope == ListingScope::Program;
                let expected = if program {
                    saved.or(Some(0x1000))
                } else {
                    Some(0x1000)
                };
                assert_eq!(app.selected, expected, "{scope:?} {saved:?}");
                assert_eq!(app.tab, Tab::Listing);
            }
        }
        // A current displayed entry opens instead.
        let mut app = opened(ListingScope::Program);
        let saved = project(&app, None, Some(0x1020), Some(0x1040));
        restore(&mut app, saved);
        assert_eq!(app.result_scope, Some(0x1040));
        assert_eq!(app.selected, Some(0x1020));
    }

    #[test]
    fn function_scope_restores_the_saved_function_without_landing() {
        let mut app = opened(ListingScope::Function);
        let saved = project(&app, Some(view(0x1000, 4)), Some(0x1020), Some(0x1000));
        restore(&mut app, saved);
        assert_eq!(app.view().map(|view| view.address), Some(0x1000));
        assert_eq!((app.selected, app.tab), (Some(0x1000), Tab::Listing));
        assert!(!graph_requested_any(&app), "{:?}", app.queue);
        assert!(app.program.cursor.is_none() && app.program.landing.is_none());
        assert_eq!(app.pending_listing_scroll, Some(0));
        // Saved data in a non-code section never opens a function either.
        let mut app = opened(ListingScope::Function);
        let saved = project(&app, None, Some(0x2010), Some(0x1000));
        restore(&mut app, saved);
        assert_eq!(
            (app.result_scope, app.selected),
            (Some(0x1000), Some(0x1000))
        );
        assert!(!graph_requested(&app, 0x2010));
    }

    #[test]
    fn saving_keeps_the_exact_file_backed_selection() {
        let context = egui::Context::default();
        let mut app = opened(ListingScope::Program);
        let saved = project(&app, Some(view(0x1000, 4)), Some(0x1000), Some(0x1000));
        restore(&mut app, saved);
        assert_eq!(app.project_selection(), Some(0x1000));
        for address in [0x1020, 0x2010] {
            assert!(app.land_in_listing(address, 1, None, false, &context));
            assert_eq!(app.project_selection(), Some(address), "{address:#x}");
        }
        // Hex keeps the listing selection it departed from.
        app.open_data(0x2030, 4, &context);
        assert_eq!(app.project_selection(), Some(0x2010));
        // Zero-filled bytes have no file-backed address to save.
        app.data_location = None;
        app.code_selection = None;
        app.selected = Some(0x3010);
        assert_eq!(app.project_selection(), Some(0x1000));
    }
}
