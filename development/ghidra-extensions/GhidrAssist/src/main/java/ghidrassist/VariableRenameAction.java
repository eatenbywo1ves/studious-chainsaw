package ghidrassist;

import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import docking.action.MenuData;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;

public class VariableRenameAction extends ListingContextAction {
    private final GhidrAssistPlugin plugin;

    public VariableRenameAction(GhidrAssistPlugin plugin) {
        super("AI Suggest Variable Names", plugin.getName());
        this.plugin = plugin;

        setPopupMenuData(new MenuData(
            new String[] {"GhidrAssist", "Suggest Variable Names"},
            "AI"
        ));
    }

    @Override
    protected void actionPerformed(ListingActionContext context) {
        if (context.getProgram() == null) {
            return;
        }

        // Get function at current location
        Function function = context.getProgram().getFunctionManager()
            .getFunctionContaining(context.getAddress());

        if (function == null) {
            return;
        }

        // Get current variables
        Variable[] variables = function.getAllVariables();
        if (variables.length == 0) {
            plugin.showError("No variables found in function " + function.getName());
            return;
        }

        List<String> currentNames = new ArrayList<>();
        for (Variable var : variables) {
            currentNames.add(var.getName());
        }

        // Get AI suggestions via MCP
        plugin.showProgress("Analyzing function for better variable names...");

        // Execute in background thread
        new Thread(() -> {
            try {
                String functionCode = plugin.getFunctionDecompilation(function);
                String[] suggestions = plugin.getMCPClient().suggestVariableNames(
                    currentNames.toArray(new String[0]),
                    functionCode
                );

                // Show suggestions dialog on UI thread
                SwingUtilities.invokeLater(() -> {
                    showRenamingDialog(function, variables, suggestions, context);
                });

            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    plugin.showError("Failed to get suggestions: " + e.getMessage());
                });
            }
        }).start();
    }

    private void showRenamingDialog(Function function, Variable[] variables,
                                     String[] suggestions, ListingActionContext context) {
        // Create dialog
        JDialog dialog = new JDialog();
        dialog.setTitle("GhidrAssist - AI Variable Renaming Suggestions");
        dialog.setModal(true);
        dialog.setSize(700, 500);
        dialog.setLocationRelativeTo(null);

        // Create table with custom model
        String[] columnNames = {"Current Name", "Suggested Name", "Type", "Apply"};
        DefaultTableModel tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public Class<?> getColumnClass(int column) {
                if (column == 3) return Boolean.class;
                return String.class;
            }

            @Override
            public boolean isCellEditable(int row, int column) {
                // Only "Apply" column is editable
                return column == 3;
            }
        };

        // Populate table
        for (int i = 0; i < variables.length; i++) {
            Object[] row = new Object[4];
            row[0] = variables[i].getName();
            row[1] = i < suggestions.length ? suggestions[i] : "No suggestion";
            row[2] = variables[i].getDataType().getName();
            row[3] = Boolean.TRUE; // Default: apply all
            tableModel.addRow(row);
        }

        JTable table = new JTable(tableModel);
        table.setRowHeight(25);
        table.getColumnModel().getColumn(0).setPreferredWidth(150);
        table.getColumnModel().getColumn(1).setPreferredWidth(200);
        table.getColumnModel().getColumn(2).setPreferredWidth(120);
        table.getColumnModel().getColumn(3).setPreferredWidth(80);

        JScrollPane scrollPane = new JScrollPane(table);

        // Info panel
        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        JLabel infoLabel = new JLabel(
            String.format("<html><b>Function:</b> %s | <b>Variables:</b> %d | " +
                         "<b>Suggestions:</b> %d</html>",
                         function.getName(), variables.length, suggestions.length)
        );
        infoPanel.add(infoLabel, BorderLayout.WEST);

        // Buttons panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));

        JButton selectAllButton = new JButton("Select All");
        JButton deselectAllButton = new JButton("Deselect All");
        JButton applyButton = new JButton("Apply Selected");
        JButton cancelButton = new JButton("Cancel");

        selectAllButton.addActionListener(e -> {
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                tableModel.setValueAt(Boolean.TRUE, i, 3);
            }
        });

        deselectAllButton.addActionListener(e -> {
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                tableModel.setValueAt(Boolean.FALSE, i, 3);
            }
        });

        applyButton.addActionListener(e -> {
            applyRenamings(function, variables, tableModel, context);
            dialog.dispose();
        });

        cancelButton.addActionListener(e -> dialog.dispose());

        buttonPanel.add(selectAllButton);
        buttonPanel.add(deselectAllButton);
        buttonPanel.add(applyButton);
        buttonPanel.add(cancelButton);

        // Layout
        dialog.setLayout(new BorderLayout());
        dialog.add(infoPanel, BorderLayout.NORTH);
        dialog.add(scrollPane, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);

        dialog.setVisible(true);
    }

    private void applyRenamings(Function function, Variable[] variables,
                                DefaultTableModel tableModel, ListingActionContext context) {
        int appliedCount = 0;
        int failedCount = 0;
        StringBuilder errors = new StringBuilder();

        // Start transaction for atomic changes
        int transactionID = function.getProgram().startTransaction("AI Variable Renaming");
        boolean success = false;

        try {
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                Boolean apply = (Boolean) tableModel.getValueAt(i, 3);

                if (apply != null && apply) {
                    String newName = (String) tableModel.getValueAt(i, 1);

                    if (newName != null && !newName.equals("No suggestion") &&
                        !newName.equals(variables[i].getName())) {
                        try {
                            // Apply renaming
                            variables[i].setName(newName, SourceType.USER_DEFINED);
                            appliedCount++;
                        } catch (DuplicateNameException e) {
                            failedCount++;
                            errors.append(String.format("Duplicate name '%s'\n", newName));
                        } catch (InvalidInputException e) {
                            failedCount++;
                            errors.append(String.format("Invalid name '%s': %s\n",
                                                       newName, e.getMessage()));
                        }
                    }
                }
            }

            success = true;

        } finally {
            function.getProgram().endTransaction(transactionID, success);
        }

        // Show summary
        if (failedCount > 0) {
            String message = String.format(
                "Applied %d renamings, %d failed.\n\nErrors:\n%s",
                appliedCount, failedCount, errors.toString()
            );
            JOptionPane.showMessageDialog(null, message, "Renaming Results",
                                         JOptionPane.WARNING_MESSAGE);
        } else {
            plugin.showSuccess(String.format("Successfully applied %d variable renamings in %s",
                                           appliedCount, function.getName()));
        }
    }

    @Override
    protected boolean isEnabledForContext(ListingActionContext context) {
        // Enable only when cursor is on a function
        if (context.getProgram() == null || context.getAddress() == null) {
            return false;
        }

        return context.getProgram().getFunctionManager()
            .getFunctionContaining(context.getAddress()) != null;
    }
}
