package ghidrassist;

import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;

public class FunctionExplanationAction extends ListingContextAction {
    private final GhidrAssistPlugin plugin;

    public FunctionExplanationAction(GhidrAssistPlugin plugin) {
        super("Explain Function (AI)", plugin.getName());
        this.plugin = plugin;

        // Add to right-click menu
        setPopupMenuData(new MenuData(
            new String[] {"GhidrAssist", "Explain Function"},
            "AI"
        ));

        setEnabled(true);
    }

    @Override
    protected void actionPerformed(ListingActionContext context) {
        if (context.getProgram() == null) {
            return;
        }

        // Get function at current location
        Function function = context.getProgram().getFunctionManager()
            .getFunctionContaining(context.getAddress());

        if (function != null) {
            // Trigger AI explanation
            plugin.explainFunction(function);
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
