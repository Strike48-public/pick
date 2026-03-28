//! Tests for CyberChef sortable drag-and-drop logic
//!
//! These tests verify the correctness of the drag-and-drop reordering algorithm
//! to ensure operations are inserted at the correct position.

#[cfg(test)]
mod tests {
    /// Simulates the drag-and-drop reorder logic
    fn reorder_items<T: Clone>(
        items: &mut Vec<T>,
        from_idx: usize,
        target_idx: usize,
        insert_before: bool,
    ) {
        if from_idx >= items.len() || target_idx >= items.len() {
            return;
        }

        // Don't do anything if dropping on itself
        let should_move = if insert_before {
            from_idx != target_idx
        } else {
            from_idx != target_idx && from_idx != target_idx + 1
        };

        if !should_move {
            return;
        }

        let item = items.remove(from_idx);

        // Calculate final insert position after removal
        let insert_at = if insert_before {
            // Insert before target
            if from_idx < target_idx {
                // Moving forward: target shifts back by 1 after removal
                target_idx - 1
            } else {
                // Moving backward: target stays same
                target_idx
            }
        } else {
            // Insert after target
            if from_idx < target_idx {
                // Moving forward: target shifts back but we want after it
                target_idx
            } else {
                // Moving backward: target stays same, insert after it
                target_idx + 1
            }
        };

        items.insert(insert_at, item);
    }

    #[test]
    fn test_drag_first_to_second_before() {
        // [A, B, C] -> drag A before B -> [A, B, C] (no change)
        let mut items = vec!["A", "B", "C"];
        reorder_items(&mut items, 0, 1, true);
        assert_eq!(items, vec!["A", "B", "C"]);
    }

    #[test]
    fn test_drag_first_to_second_after() {
        // [A, B, C] -> drag A after B -> [B, A, C]
        let mut items = vec!["A", "B", "C"];
        reorder_items(&mut items, 0, 1, false);
        assert_eq!(items, vec!["B", "A", "C"]);
    }

    #[test]
    fn test_drag_first_to_third_before() {
        // [A, B, C] -> drag A before C -> [B, A, C]
        let mut items = vec!["A", "B", "C"];
        reorder_items(&mut items, 0, 2, true);
        assert_eq!(items, vec!["B", "A", "C"]);
    }

    #[test]
    fn test_drag_first_to_third_after() {
        // [A, B, C] -> drag A after C -> [B, C, A]
        let mut items = vec!["A", "B", "C"];
        reorder_items(&mut items, 0, 2, false);
        assert_eq!(items, vec!["B", "C", "A"]);
    }

    #[test]
    fn test_drag_second_to_first_before() {
        // [A, B, C] -> drag B before A -> [B, A, C]
        let mut items = vec!["A", "B", "C"];
        reorder_items(&mut items, 1, 0, true);
        assert_eq!(items, vec!["B", "A", "C"]);
    }

    #[test]
    fn test_drag_second_to_first_after() {
        // [A, B, C] -> drag B after A -> [A, B, C] (no change)
        let mut items = vec!["A", "B", "C"];
        reorder_items(&mut items, 1, 0, false);
        assert_eq!(items, vec!["A", "B", "C"]);
    }

    #[test]
    fn test_drag_second_to_third_before() {
        // [A, B, C] -> drag B before C -> [A, B, C] (no change)
        let mut items = vec!["A", "B", "C"];
        reorder_items(&mut items, 1, 2, true);
        assert_eq!(items, vec!["A", "B", "C"]);
    }

    #[test]
    fn test_drag_second_to_third_after() {
        // [A, B, C] -> drag B after C -> [A, C, B]
        let mut items = vec!["A", "B", "C"];
        reorder_items(&mut items, 1, 2, false);
        assert_eq!(items, vec!["A", "C", "B"]);
    }

    #[test]
    fn test_drag_third_to_first_before() {
        // [A, B, C] -> drag C before A -> [C, A, B]
        let mut items = vec!["A", "B", "C"];
        reorder_items(&mut items, 2, 0, true);
        assert_eq!(items, vec!["C", "A", "B"]);
    }

    #[test]
    fn test_drag_third_to_first_after() {
        // [A, B, C] -> drag C after A -> [A, C, B]
        let mut items = vec!["A", "B", "C"];
        reorder_items(&mut items, 2, 0, false);
        assert_eq!(items, vec!["A", "C", "B"]);
    }

    #[test]
    fn test_drag_third_to_second_before() {
        // [A, B, C] -> drag C before B -> [A, C, B]
        let mut items = vec!["A", "B", "C"];
        reorder_items(&mut items, 2, 1, true);
        assert_eq!(items, vec!["A", "C", "B"]);
    }

    #[test]
    fn test_drag_third_to_second_after() {
        // [A, B, C] -> drag C after B -> [A, B, C] (no change)
        let mut items = vec!["A", "B", "C"];
        reorder_items(&mut items, 2, 1, false);
        assert_eq!(items, vec!["A", "B", "C"]);
    }

    #[test]
    fn test_drag_onto_self_before() {
        // [A, B, C] -> drag B before B -> [A, B, C] (no change)
        let mut items = vec!["A", "B", "C"];
        reorder_items(&mut items, 1, 1, true);
        assert_eq!(items, vec!["A", "B", "C"]);
    }

    #[test]
    fn test_drag_onto_self_after() {
        // [A, B, C] -> drag B after B -> [A, B, C] (no change)
        let mut items = vec!["A", "B", "C"];
        reorder_items(&mut items, 1, 1, false);
        assert_eq!(items, vec!["A", "B", "C"]);
    }

    #[test]
    fn test_longer_list_forward() {
        // [A, B, C, D, E] -> drag A before D -> [B, C, A, D, E]
        let mut items = vec!["A", "B", "C", "D", "E"];
        reorder_items(&mut items, 0, 3, true);
        assert_eq!(items, vec!["B", "C", "A", "D", "E"]);
    }

    #[test]
    fn test_longer_list_backward() {
        // [A, B, C, D, E] -> drag E before B -> [A, E, B, C, D]
        let mut items = vec!["A", "B", "C", "D", "E"];
        reorder_items(&mut items, 4, 1, true);
        assert_eq!(items, vec!["A", "E", "B", "C", "D"]);
    }

    #[test]
    fn test_edge_case_two_items_swap() {
        // [A, B] -> drag A after B -> [B, A]
        let mut items = vec!["A", "B"];
        reorder_items(&mut items, 0, 1, false);
        assert_eq!(items, vec!["B", "A"]);
    }

    #[test]
    fn test_edge_case_single_item() {
        // [A] -> drag A before A -> [A] (no change)
        let mut items = vec!["A"];
        reorder_items(&mut items, 0, 0, true);
        assert_eq!(items, vec!["A"]);
    }
}
