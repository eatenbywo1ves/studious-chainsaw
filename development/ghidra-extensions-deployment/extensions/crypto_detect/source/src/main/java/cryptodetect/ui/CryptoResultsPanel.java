package cryptodetect.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;

import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.table.GhidraTable;

import cryptodetect.CryptoDetectPlugin;
import cryptodetect.analyzers.CryptoRoutineAnalyzer.CryptoDetection;

/**
 * Panel for displaying cryptographic analysis results in a table format.
 * Supports sorting, filtering, and navigation to detected crypto routines.
 */
public class CryptoResultsPanel extends JPanel {
    
    private final CryptoDetectPlugin plugin;
    private final GhidraTable resultsTable;
    private final CryptoDetectionTableModel tableModel;
    private final JLabel statusLabel;
    
    public CryptoResultsPanel(CryptoDetectPlugin plugin) {
        super(new BorderLayout());
        this.plugin = plugin;
        
        // Initialize table model and table
        this.tableModel = new CryptoDetectionTableModel();
        this.resultsTable = new GhidraTable(tableModel);
        this.statusLabel = new JLabel("Ready", SwingConstants.CENTER);
        
        setupTable();
        buildPanel();
    }
    
    /**
     * Configure the results table.
     */
    private void setupTable() {
        // Table configuration
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.setAutoCreateRowSorter(true);
        resultsTable.getTableHeader().setReorderingAllowed(true);
        
        // Column widths
        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(120); // Address
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(150); // Algorithm
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(80);  // Confidence
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(100); // Type
        resultsTable.getColumnModel().getColumn(4).setPreferredWidth(300); // Description
        
        // Custom cell renderers
        resultsTable.getColumnModel().getColumn(2).setCellRenderer(new ConfidenceCellRenderer());
        resultsTable.getColumnModel().getColumn(3).setCellRenderer(new TypeCellRenderer());
        
        // Double-click handler for navigation
        resultsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    navigateToSelection();
                }
            }
        });
    }
    
    /**
     * Build the panel layout.
     */
    private void buildPanel() {
        // Status label styling
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.ITALIC));
        statusLabel.setForeground(Color.GRAY);
        
        // Add components
        add(new JScrollPane(resultsTable), BorderLayout.CENTER);
        add(statusLabel, BorderLayout.SOUTH);
    }
    
    /**
     * Set the analysis results to display.
     */
    public void setResults(List<CryptoDetection> detections) {
        tableModel.setDetections(detections);
        updateStatusMessage();
    }
    
    /**
     * Clear all results from the table.
     */
    public void clearResults() {
        tableModel.clearDetections();
        setStatusMessage("No results");
    }
    
    /**
     * Set status message.
     */
    public void setStatusMessage(String message) {
        statusLabel.setText(message);
    }
    
    /**
     * Update status message based on current results.
     */
    private void updateStatusMessage() {
        int count = tableModel.getRowCount();
        if (count == 0) {
            setStatusMessage("No cryptographic routines detected");
        } else if (count == 1) {
            setStatusMessage("1 detection found");
        } else {
            setStatusMessage(count + " detections found");
        }
    }
    
    /**
     * Navigate to the selected detection in Ghidra's main view.
     */
    private void navigateToSelection() {
        int selectedRow = resultsTable.getSelectedRow();
        if (selectedRow >= 0) {
            // Convert view row to model row (accounting for sorting)
            int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
            CryptoDetection detection = tableModel.getDetectionAt(modelRow);
            
            if (detection != null && plugin.getCurrentProgram() != null) {
                // Navigate to the address
                Address address = detection.getAddress();
                ProgramLocation location = new ProgramLocation(plugin.getCurrentProgram(), address);
                plugin.getGoToService().goTo(location);
                
                plugin.getConsoleService().println(
                    "[CryptoDetect] Navigated to " + detection.getAlgorithmName() + " at " + address);
            }
        }
    }
    
    /**
     * Get the currently selected detection.
     */
    public CryptoDetection getSelectedDetection() {
        int selectedRow = resultsTable.getSelectedRow();
        if (selectedRow >= 0) {
            int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
            return tableModel.getDetectionAt(modelRow);
        }
        return null;
    }
    
    /**
     * Dispose of resources.
     */
    public void dispose() {
        // Clean up any resources if needed
    }
    
    /**
     * Table model for crypto detections.
     */
    private static class CryptoDetectionTableModel extends AbstractTableModel {
        private static final String[] COLUMN_NAMES = {
            "Address", "Algorithm", "Confidence", "Type", "Description"
        };
        
        private List<CryptoDetection> detections = List.of();
        
        public void setDetections(List<CryptoDetection> detections) {
            this.detections = detections;
            fireTableDataChanged();
        }
        
        public void clearDetections() {
            this.detections = List.of();
            fireTableDataChanged();
        }
        
        public CryptoDetection getDetectionAt(int row) {
            if (row >= 0 && row < detections.size()) {
                return detections.get(row);
            }
            return null;
        }
        
        @Override
        public int getRowCount() {
            return detections.size();
        }
        
        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.length;
        }
        
        @Override
        public String getColumnName(int column) {
            return COLUMN_NAMES[column];
        }
        
        @Override
        public Class<?> getColumnClass(int columnIndex) {
            switch (columnIndex) {
                case 0: return Address.class;
                case 1: return String.class;
                case 2: return Double.class;
                case 3: return CryptoDetection.DetectionType.class;
                case 4: return String.class;
                default: return String.class;
            }
        }
        
        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex >= detections.size()) return null;
            
            CryptoDetection detection = detections.get(rowIndex);
            switch (columnIndex) {
                case 0: return detection.getAddress();
                case 1: return detection.getAlgorithmName();
                case 2: return detection.getConfidence();
                case 3: return detection.getType();
                case 4: return detection.getDescription();
                default: return "";
            }
        }
    }
    
    /**
     * Cell renderer for confidence values with color coding.
     */
    private static class ConfidenceCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {
            
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            
            if (value instanceof Double) {
                double confidence = (Double) value;
                setText(String.format("%.1f%%", confidence * 100));
                
                if (!isSelected) {
                    // Color code confidence levels
                    if (confidence >= 0.8) {
                        setBackground(new Color(200, 255, 200)); // Light green
                    } else if (confidence >= 0.6) {
                        setBackground(new Color(255, 255, 200)); // Light yellow
                    } else {
                        setBackground(new Color(255, 220, 220)); // Light red
                    }
                } else {
                    setBackground(table.getSelectionBackground());
                }
            }
            
            return c;
        }
    }
    
    /**
     * Cell renderer for detection types with formatting.
     */
    private static class TypeCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {
            
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            
            if (value instanceof CryptoDetection.DetectionType) {
                CryptoDetection.DetectionType type = (CryptoDetection.DetectionType) value;
                setText(formatDetectionType(type));
                
                if (!isSelected) {
                    // Color code detection types
                    switch (type) {
                        case PATTERN_MATCH:
                            setBackground(new Color(220, 255, 220)); // Light green
                            break;
                        case CONSTANT_MATCH:
                            setBackground(new Color(220, 220, 255)); // Light blue
                            break;
                        case ENTROPY_ANALYSIS:
                            setBackground(new Color(255, 220, 255)); // Light purple
                            break;
                        case STRUCTURE_ANALYSIS:
                            setBackground(new Color(255, 240, 220)); // Light orange
                            break;
                        default:
                            setBackground(table.getBackground());
                    }
                } else {
                    setBackground(table.getSelectionBackground());
                }
            }
            
            return c;
        }
        
        private String formatDetectionType(CryptoDetection.DetectionType type) {
            switch (type) {
                case PATTERN_MATCH: return "Pattern";
                case CONSTANT_MATCH: return "Constant";
                case ENTROPY_ANALYSIS: return "Entropy";
                case STRUCTURE_ANALYSIS: return "Structure";
                case HEURISTIC: return "Heuristic";
                default: return type.toString();
            }
        }
    }
}