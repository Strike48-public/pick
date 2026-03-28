//! CyberChef page — data transformation and analysis tool with recipe chaining

use dioxus::prelude::*;
use pentest_core::tools::ToolContext;

/// Recipe metadata for the UI
#[derive(Clone, PartialEq)]
struct RecipeInfo {
    name: &'static str,
    category: &'static str,
    description: &'static str,
    example: &'static str,
}

/// Recipe chain item with enable/disable state
#[derive(Clone, PartialEq)]
struct ChainItem {
    recipe_idx: usize,
    enabled: bool,
}

/// Dragging state - tracks what's being dragged
#[derive(Clone, PartialEq, Debug)]
enum DragItem {
    /// Dragging from operations panel (recipe_idx)
    FromOperations(usize),
    /// Dragging from recipe chain (index in chain)
    FromChain(usize),
}

const RECIPES: &[RecipeInfo] = &[
    // Encoding/Decoding
    RecipeInfo {
        name: "base64_decode",
        category: "Encoding",
        description: "Decode Base64 encoded data",
        example: "SGVsbG8gV29ybGQ=",
    },
    RecipeInfo {
        name: "base64_encode",
        category: "Encoding",
        description: "Encode data to Base64",
        example: "Hello World",
    },
    RecipeInfo {
        name: "url_decode",
        category: "Encoding",
        description: "Decode URL encoded data",
        example: "Hello%20World%21",
    },
    RecipeInfo {
        name: "url_encode",
        category: "Encoding",
        description: "Encode data for URLs",
        example: "Hello World!",
    },
    RecipeInfo {
        name: "hex_decode",
        category: "Encoding",
        description: "Decode hexadecimal to text",
        example: "48656c6c6f",
    },
    RecipeInfo {
        name: "hex_encode",
        category: "Encoding",
        description: "Encode text to hexadecimal",
        example: "Hello",
    },
    // Hashing
    RecipeInfo {
        name: "hash_md5",
        category: "Hashing",
        description: "Calculate MD5 hash",
        example: "password123",
    },
    RecipeInfo {
        name: "hash_sha1",
        category: "Hashing",
        description: "Calculate SHA-1 hash",
        example: "password123",
    },
    RecipeInfo {
        name: "hash_sha256",
        category: "Hashing",
        description: "Calculate SHA-256 hash",
        example: "password123",
    },
    RecipeInfo {
        name: "hash_all",
        category: "Hashing",
        description: "Calculate all common hashes (MD5, SHA-1, SHA-256)",
        example: "password123",
    },
    // Cryptography
    RecipeInfo {
        name: "xor_bruteforce",
        category: "Cryptography",
        description: "Brute force XOR cipher with single-byte keys (1-255)",
        example: "\\x1c\\x00\\x1f\\x1f\\x14",
    },
    RecipeInfo {
        name: "rot13",
        category: "Cryptography",
        description: "Apply ROT13 cipher",
        example: "Hello World",
    },
    // Data Extraction
    RecipeInfo {
        name: "extract_urls",
        category: "Extraction",
        description: "Extract all URLs from text",
        example: "Check out https://example.com and http://test.org",
    },
    RecipeInfo {
        name: "extract_ips",
        category: "Extraction",
        description: "Extract all IP addresses from text",
        example: "Servers: 192.168.1.1 and 10.0.0.1",
    },
    RecipeInfo {
        name: "extract_emails",
        category: "Extraction",
        description: "Extract all email addresses from text",
        example: "Contact: admin@example.com or support@test.org",
    },
    RecipeInfo {
        name: "extract_domains",
        category: "Extraction",
        description: "Extract all domain names from text",
        example: "Visit example.com and test.org for more info",
    },
    // Compression
    RecipeInfo {
        name: "gzip_decompress",
        category: "Compression",
        description: "Decompress gzip compressed data",
        example: "(gzip compressed bytes)",
    },
    RecipeInfo {
        name: "zlib_decompress",
        category: "Compression",
        description: "Decompress zlib compressed data",
        example: "(zlib compressed bytes)",
    },
    // Analysis
    RecipeInfo {
        name: "magic",
        category: "Analysis",
        description: "Auto-detect encoding/compression and decode",
        example: "SGVsbG8gV29ybGQ=",
    },
    RecipeInfo {
        name: "jwt_decode",
        category: "Web",
        description: "Decode JWT token and display header/payload",
        // gitleaks:allow - Example JWT token for demonstration, not a real secret
        example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    },
];

/// CyberChef page - interactive data transformation tool with recipe chaining
#[component]
pub fn CyberChefPage() -> Element {
    let mut recipe_chain = use_signal(|| Vec::<ChainItem>::new());
    let mut search_query = use_signal(String::new);
    let mut input_text = use_signal(String::new);
    let mut output_text = use_signal(String::new);
    let mut error_message = use_signal(|| None::<String>);
    let mut is_executing = use_signal(|| false);
    let mut auto_bake = use_signal(|| true);
    let mut input_panel_height = use_signal(|| 50.0); // Percentage
    let mut is_resizing = use_signal(|| false);

    // Sortable state
    let mut dragging_item = use_signal(|| None::<DragItem>);
    let mut drag_over_slot = use_signal(|| None::<usize>); // Slot index (0 = before first, n = after last)
    let mut is_dragging_outside = use_signal(|| false); // Track if mouse is outside recipe area

    // Group recipes by category
    let categories = vec![
        "Encoding",
        "Hashing",
        "Cryptography",
        "Extraction",
        "Compression",
        "Analysis",
        "Web",
    ];

    // Filter recipes based on search
    let filtered_recipes: Vec<(usize, &RecipeInfo)> = RECIPES
        .iter()
        .enumerate()
        .filter(|(_, recipe)| {
            let query = search_query.read().to_lowercase();
            query.is_empty()
                || recipe.name.to_lowercase().contains(&query)
                || recipe.description.to_lowercase().contains(&query)
        })
        .collect();

    let mut execute_recipe_chain = move || {
        let chain = recipe_chain.read().clone();
        let input = input_text.read().clone();

        if input.is_empty() {
            output_text.set(String::new());
            error_message.set(None);
            return;
        }

        if chain.is_empty() {
            error_message.set(Some(
                "No operations in recipe chain. Add operations from the left panel.".to_string(),
            ));
            return;
        }

        is_executing.set(true);
        error_message.set(None);

        spawn(async move {
            let registry_arc = match crate::session::get_tool_registry() {
                Some(r) => r,
                None => {
                    error_message.set(Some("Tool registry not available".to_string()));
                    is_executing.set(false);
                    return;
                }
            };

            let ctx = ToolContext::default();
            let registry_guard = registry_arc.read().await;

            // Execute chain: pipe output of each operation to the next (skip disabled)
            let mut current_data = input;

            for (step_num, item) in chain.iter().enumerate() {
                if !item.enabled {
                    continue; // Skip disabled operations
                }

                let recipe = &RECIPES[item.recipe_idx];

                let params = serde_json::json!({
                    "recipe": recipe.name,
                    "input": current_data,
                });

                match registry_guard.execute("cyberchef", params, &ctx).await {
                    Ok(result) => {
                        if let Some(output) = result.data.get("output").and_then(|v| v.as_str()) {
                            current_data = output.to_string();
                        } else if let Some(results) = result.data.get("results") {
                            current_data =
                                serde_json::to_string_pretty(&results).unwrap_or_default();
                        } else {
                            current_data =
                                serde_json::to_string_pretty(&result.data).unwrap_or_default();
                        }
                    }
                    Err(e) => {
                        error_message.set(Some(format!(
                            "Step {} ({}) failed: {}",
                            step_num + 1,
                            recipe.name,
                            e
                        )));
                        output_text.set(current_data);
                        is_executing.set(false);
                        return;
                    }
                }
            }

            output_text.set(current_data);
            error_message.set(None);
            is_executing.set(false);
        });
    };

    let load_example = move |_| {
        let chain = recipe_chain.read();
        if let Some(first_item) = chain.first() {
            let recipe = &RECIPES[first_item.recipe_idx];
            input_text.set(recipe.example.to_string());
            if *auto_bake.read() {
                execute_recipe_chain();
            }
        }
    };

    let mut add_to_chain = move |recipe_idx: usize| {
        let mut chain = recipe_chain.write();
        chain.push(ChainItem {
            recipe_idx,
            enabled: true,
        });
        drop(chain);

        if *auto_bake.read() && !input_text.read().is_empty() {
            execute_recipe_chain();
        }
    };

    let mut remove_from_chain = move |index: usize| {
        let mut chain = recipe_chain.write();
        chain.remove(index);
        drop(chain);

        if *auto_bake.read() && !input_text.read().is_empty() {
            execute_recipe_chain();
        }
    };

    let mut toggle_enabled = move |index: usize| {
        let mut chain = recipe_chain.write();
        if let Some(item) = chain.get_mut(index) {
            item.enabled = !item.enabled;
        }
        drop(chain);

        if *auto_bake.read() && !input_text.read().is_empty() {
            execute_recipe_chain();
        }
    };

    // Handle drag end - apply the changes
    let mut handle_drag_end = move || {
        let drag_item = dragging_item.read().clone();
        let slot = *drag_over_slot.read();
        let outside = *is_dragging_outside.read();

        if let Some(item) = drag_item {
            match item {
                DragItem::FromOperations(recipe_idx) => {
                    // Adding new operation from operations panel
                    if !outside {
                        if let Some(insert_at) = slot {
                            let mut chain = recipe_chain.write();
                            chain.insert(
                                insert_at,
                                ChainItem {
                                    recipe_idx,
                                    enabled: true,
                                },
                            );
                            drop(chain);
                        } else {
                            // No slot, append to end
                            let mut chain = recipe_chain.write();
                            chain.push(ChainItem {
                                recipe_idx,
                                enabled: true,
                            });
                            drop(chain);
                        }

                        if *auto_bake.read() && !input_text.read().is_empty() {
                            execute_recipe_chain();
                        }
                    }
                }
                DragItem::FromChain(from_idx) => {
                    // Reordering within recipe
                    if outside {
                        // Remove if dragged outside
                        let mut chain = recipe_chain.write();
                        chain.remove(from_idx);
                        drop(chain);

                        if *auto_bake.read() && !input_text.read().is_empty() {
                            execute_recipe_chain();
                        }
                    } else if let Some(target_slot) = slot {
                        // Reorder within recipe using slot positions
                        if from_idx != target_slot && target_slot != from_idx + 1 {
                            let mut chain = recipe_chain.write();
                            let item = chain.remove(from_idx);

                            // Adjust target slot after removal
                            let insert_at = if from_idx < target_slot {
                                target_slot - 1
                            } else {
                                target_slot
                            };

                            chain.insert(insert_at, item);
                            drop(chain);

                            if *auto_bake.read() && !input_text.read().is_empty() {
                                execute_recipe_chain();
                            }
                        }
                    }
                }
            }
        }

        // Clear drag state
        dragging_item.set(None);
        drag_over_slot.set(None);
        is_dragging_outside.set(false);
    };

    let clear_chain = move |_| {
        recipe_chain.set(Vec::new());
        output_text.set(String::new());
        error_message.set(None);
    };

    let on_input_change = move |evt: Event<FormData>| {
        input_text.set(evt.value());
        if *auto_bake.read() && !recipe_chain.read().is_empty() {
            execute_recipe_chain();
        }
    };

    let mut resize_start_y = use_signal(|| 0.0);
    let mut resize_start_height = use_signal(|| 50.0);

    let start_resize = move |evt: Event<MouseData>| {
        is_resizing.set(true);
        resize_start_y.set(evt.page_coordinates().y);
        resize_start_height.set(*input_panel_height.read());
    };

    let stop_resize = move |_| {
        is_resizing.set(false);
    };

    let handle_resize = move |evt: Event<MouseData>| {
        if *is_resizing.read() {
            let current_y = evt.page_coordinates().y;
            let delta_y = current_y - *resize_start_y.read();

            // Approximate: 1% per 8 pixels of movement (adjust based on typical window height)
            let delta_percentage = delta_y / 8.0;
            let mut new_percentage = *resize_start_height.read() + delta_percentage;

            // Clamp between 20% and 80%
            new_percentage = new_percentage.max(20.0).min(80.0);

            input_panel_height.set(new_percentage);
        }
    };

    rsx! {
        style { {include_str!("css/cyberchef_page.css")} }

        div { class: "cyberchef-page",
            // Left sidebar - Operations library
            div { class: "recipe-library",
                div { class: "library-header",
                    "Operations"
                }
                div { class: "recipe-search",
                    input {
                        r#type: "text",
                        placeholder: "Search operations...",
                        value: "{search_query}",
                        oninput: move |evt| search_query.set(evt.value()),
                    }
                }

                div { class: "recipe-categories",
                    for category_name in categories.iter() {
                        {
                            let category_recipes: Vec<_> = filtered_recipes
                                .iter()
                                .filter(|(_, r)| r.category == *category_name)
                                .collect();

                            if !category_recipes.is_empty() {
                                rsx! {
                                    div { class: "recipe-category",
                                        div { class: "category-header", "{category_name}" }
                                        for (idx, recipe) in category_recipes {
                                            {
                                                let recipe_idx = *idx;
                                                rsx! {
                                                    div {
                                                        class: "recipe-item",
                                                        draggable: true,
                                                        onclick: move |_| add_to_chain(recipe_idx),
                                                        ondragstart: move |_| {
                                                            dragging_item.set(Some(DragItem::FromOperations(recipe_idx)));
                                                        },
                                                        ondragend: move |_| {
                                                            handle_drag_end();
                                                        },
                                                        span { class: "recipe-name", "{recipe.name}" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                rsx! { }
                            }
                        }
                    }
                }
            }

            // Middle panel - Recipe chain
            div { class: "recipe-chain-panel",
                div { class: "recipe-chain-header",
                    span { "Recipe" }
                    if !recipe_chain.read().is_empty() {
                        button {
                            class: "clear-recipe-btn",
                            onclick: load_example,
                            "Load Example"
                        }
                        button {
                            class: "clear-recipe-btn",
                            onclick: clear_chain,
                            "Clear"
                        }
                    }
                }

                div {
                    class: "recipe-chain-area",
                    ondragover: move |evt| {
                        evt.prevent_default();
                        is_dragging_outside.set(false);
                    },
                    ondragleave: move |_| {
                        is_dragging_outside.set(true);
                        drag_over_slot.set(None);
                    },
                    ondragenter: move |_| {
                        is_dragging_outside.set(false);
                    },

                    if recipe_chain.read().is_empty() {
                        div { class: "recipe-chain-empty",
                            div { class: "recipe-chain-empty-icon", "⚡" }
                            div {
                                "Drag operations from the left or click to build your recipe chain."
                            }
                            div {
                                style: "margin-top: 0.5rem; font-size: 0.75rem;",
                                "Operations will execute in order from top to bottom."
                            }
                        }
                    } else {
                        div { class: "recipe-chain-list",
                            {
                                let current_slot = *drag_over_slot.read();

                                rsx! {
                                    // Slot 0: before first item
                                    div {
                                        class: "recipe-drop-slot",
                                        ondragover: move |evt| {
                                            evt.prevent_default();
                                            evt.stop_propagation();
                                            drag_over_slot.set(Some(0));
                                            is_dragging_outside.set(false);
                                        },
                                        if current_slot == Some(0) {
                                            div { class: "recipe-insert-indicator" }
                                        }
                                    }

                                    // Items with slots after each
                                    for (index, item) in recipe_chain.read().iter().enumerate() {
                                        {
                                            let recipe = &RECIPES[item.recipe_idx];
                                            let item_index = index;
                                            let is_enabled = item.enabled;
                                            let is_dragging_this = dragging_item.read().as_ref()
                                                .map_or(false, |d| matches!(d, DragItem::FromChain(i) if *i == item_index));
                                            let slot_after = index + 1;

                                            rsx! {
                                                // The recipe item
                                                div {
                                                    class: "recipe-chain-item",
                                                    class: if !is_enabled { "disabled" },
                                                    class: if is_dragging_this { "dragging" },
                                                    draggable: true,
                                                    ondragstart: move |_| {
                                                        dragging_item.set(Some(DragItem::FromChain(item_index)));
                                                    },
                                                    ondragend: move |_| {
                                                        handle_drag_end();
                                                    },
                                                    div { class: "recipe-chain-number", "{index + 1}" }
                                                    div { class: "recipe-chain-content",
                                                        div { class: "recipe-chain-name", "{recipe.name}" }
                                                    }
                                                    button {
                                                        class: if is_enabled { "recipe-chain-toggle enabled" } else { "recipe-chain-toggle disabled" },
                                                        onclick: move |_| toggle_enabled(item_index),
                                                        title: if is_enabled { "Disable operation" } else { "Enable operation" },
                                                        if is_enabled { "✓" } else { "−" }
                                                    }
                                                    button {
                                                        class: "recipe-chain-remove",
                                                        onclick: move |_| remove_from_chain(item_index),
                                                        "×"
                                                    }
                                                }

                                                // Slot after this item
                                                div {
                                                    class: "recipe-drop-slot",
                                                    ondragover: move |evt| {
                                                        evt.prevent_default();
                                                        evt.stop_propagation();
                                                        drag_over_slot.set(Some(slot_after));
                                                        is_dragging_outside.set(false);
                                                    },
                                                    if current_slot == Some(slot_after) {
                                                        div { class: "recipe-insert-indicator" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Right side - Main workspace
            div { class: "cyberchef-workspace",
                // Top toolbar (removed - Auto Bake moved to Input panel header)

                // Input/Output container (vertical stack)
                div {
                    class: "io-container",
                    onmousemove: handle_resize,
                    onmouseup: stop_resize,
                    onmouseleave: stop_resize,

                    // Input panel (top)
                    div {
                        class: "io-panel input-panel",
                        style: "flex: 0 0 {input_panel_height}%;",
                        div { class: "panel-header",
                            div { class: "panel-title",
                                span { "Input" }
                            }
                            button {
                                class: if *auto_bake.read() { "btn btn-primary" } else { "btn btn-secondary" },
                                onclick: move |_| {
                                    let current = *auto_bake.read();
                                    auto_bake.set(!current);
                                },
                                if *auto_bake.read() { "Auto Bake: ON" } else { "Auto Bake: OFF" }
                            }
                            if !*auto_bake.read() {
                                button {
                                    class: "btn btn-primary",
                                    onclick: move |_| execute_recipe_chain(),
                                    disabled: is_executing.read().clone() || recipe_chain.read().is_empty(),
                                    if *is_executing.read() { "Baking..." } else { "Bake!" }
                                }
                            }
                            span { class: "panel-info", "{input_text.read().len()} bytes" }
                        }
                        if !recipe_chain.read().is_empty() {
                            div { class: "recipe-description",
                                {
                                    let chain = recipe_chain.read();
                                    if chain.len() == 1 {
                                        RECIPES[chain[0].recipe_idx].description.to_string()
                                    } else {
                                        let enabled_count = chain.iter().filter(|i| i.enabled).count();
                                        format!("{} operation chain ({} enabled)", chain.len(), enabled_count)
                                    }
                                }
                            }
                        }
                        textarea {
                            class: "io-textarea",
                            placeholder: "Enter or paste your input here...",
                            value: "{input_text}",
                            oninput: on_input_change,
                        }
                    }

                    // Resize handle
                    div {
                        class: if *is_resizing.read() { "io-resize-handle dragging" } else { "io-resize-handle" },
                        onmousedown: start_resize,
                    }

                    // Output panel (bottom)
                    div {
                        class: "io-panel output-panel",
                        style: "flex: 0 0 {100.0 - *input_panel_height.read()}%;",
                        div { class: "panel-header",
                            div { class: "panel-title",
                                span { "Output" }
                            }
                            span { class: "panel-info", "{output_text.read().len()} bytes" }
                        }
                        if let Some(error) = error_message.read().as_ref() {
                            div { class: "error-banner",
                                span { class: "error-icon", "!" }
                                span { "{error}" }
                            }
                        }
                        textarea {
                            class: "io-textarea",
                            readonly: true,
                            value: "{output_text}",
                        }
                    }
                }
            }
        }
    }
}
