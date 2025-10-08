package ghidrassist;

import javax.swing.*;
import java.awt.*;
import docking.widgets.label.GLabel;

public class ExplanationPanel extends JPanel {
    private JTextArea explanationArea;
    private JLabel statusLabel;
    private JProgressBar progressBar;

    public ExplanationPanel() {
        setLayout(new BorderLayout());

        // Status section
        JPanel statusPanel = new JPanel(new BorderLayout());
        statusLabel = new GLabel("Ready");
        progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        progressBar.setVisible(false);

        statusPanel.add(statusLabel, BorderLayout.WEST);
        statusPanel.add(progressBar, BorderLayout.CENTER);

        // Explanation text area
        explanationArea = new JTextArea();
        explanationArea.setEditable(false);
        explanationArea.setLineWrap(true);
        explanationArea.setWrapStyleWord(true);
        explanationArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

        JScrollPane scrollPane = new JScrollPane(explanationArea);

        add(statusPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
    }

    public void showExplanation(String explanation) {
        explanationArea.setText(explanation);
        statusLabel.setText("Explanation complete");
        progressBar.setVisible(false);
    }

    public void showProgress(String message) {
        statusLabel.setText(message);
        progressBar.setVisible(true);
    }

    public void showError(String error) {
        explanationArea.setText("Error: " + error);
        statusLabel.setText("Error occurred");
        progressBar.setVisible(false);
    }
}
