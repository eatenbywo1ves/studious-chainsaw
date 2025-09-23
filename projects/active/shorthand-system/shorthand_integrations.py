"""
Shorthand Auto-Response System Integrations
Practical examples for various applications
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import keyboard
import pyperclip
import time
import threading
from shorthand_autoresponder import (
    ShorthandEngine, 
    AutoResponder,
    ResponseContext,
    ShorthandRule,
    ResponseCategory,
    TriggerType
)
from shorthand_libraries import load_library
import json


class ShorthandGUI:
    """GUI application for shorthand expansion"""
    
    def __init__(self):
        self.engine = ShorthandEngine()
        self.responder = AutoResponder(self.engine)
        
        # Load default libraries
        load_library("it_support", self.engine)
        load_library("email", self.engine)
        
        # Create main window
        self.root = tk.Tk()
        self.root.title("Shorthand Auto-Response System")
        self.root.geometry("800x600")
        
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the user interface"""
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Tab 1: Text Expansion
        self.expansion_tab = ttk.Frame(notebook)
        notebook.add(self.expansion_tab, text="Text Expansion")
        self.setup_expansion_tab()
        
        # Tab 2: Rule Management
        self.rules_tab = ttk.Frame(notebook)
        notebook.add(self.rules_tab, text="Manage Rules")
        self.setup_rules_tab()
        
        # Tab 3: Statistics
        self.stats_tab = ttk.Frame(notebook)
        notebook.add(self.stats_tab, text="Statistics")
        self.setup_stats_tab()
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN)
        self.status_bar.pack(side='bottom', fill='x')
    
    def setup_expansion_tab(self):
        """Set up text expansion tab"""
        # Input frame
        input_frame = ttk.LabelFrame(self.expansion_tab, text="Input Text")
        input_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.input_text = scrolledtext.ScrolledText(input_frame, height=10)
        self.input_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Button frame
        button_frame = ttk.Frame(self.expansion_tab)
        button_frame.pack(fill='x', padx=10)
        
        ttk.Button(button_frame, text="Expand", 
                  command=self.expand_text).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Clear", 
                  command=self.clear_text).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Copy Result", 
                  command=self.copy_result).pack(side='left', padx=5)
        
        # Output frame
        output_frame = ttk.LabelFrame(self.expansion_tab, text="Expanded Text")
        output_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, height=10)
        self.output_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def setup_rules_tab(self):
        """Set up rules management tab"""
        # Rule list
        list_frame = ttk.LabelFrame(self.rules_tab, text="Active Rules")
        list_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Treeview for rules
        columns = ('Trigger', 'Expansion', 'Category', 'Usage')
        self.rules_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        
        for col in columns:
            self.rules_tree.heading(col, text=col)
            self.rules_tree.column(col, width=150)
        
        self.rules_tree.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', 
                                 command=self.rules_tree.yview)
        scrollbar.pack(side='right', fill='y')
        self.rules_tree.configure(yscrollcommand=scrollbar.set)
        
        # Add rule frame
        add_frame = ttk.LabelFrame(self.rules_tab, text="Add New Rule")
        add_frame.pack(fill='x', padx=10, pady=10)
        
        # Input fields
        ttk.Label(add_frame, text="Trigger:").grid(row=0, column=0, padx=5, pady=5)
        self.trigger_entry = ttk.Entry(add_frame, width=20)
        self.trigger_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(add_frame, text="Expansion:").grid(row=0, column=2, padx=5, pady=5)
        self.expansion_entry = ttk.Entry(add_frame, width=40)
        self.expansion_entry.grid(row=0, column=3, padx=5, pady=5)
        
        ttk.Button(add_frame, text="Add Rule", 
                  command=self.add_rule).grid(row=0, column=4, padx=5, pady=5)
        
        # Load rules button
        ttk.Button(self.rules_tab, text="Refresh Rules", 
                  command=self.load_rules).pack(pady=5)
        
        # Initial load
        self.load_rules()
    
    def setup_stats_tab(self):
        """Set up statistics tab"""
        stats_frame = ttk.LabelFrame(self.stats_tab, text="Usage Statistics")
        stats_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=20)
        self.stats_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        ttk.Button(self.stats_tab, text="Refresh Statistics", 
                  command=self.update_stats).pack(pady=5)
        
        # Initial load
        self.update_stats()
    
    def expand_text(self):
        """Expand shorthand in input text"""
        input_text = self.input_text.get('1.0', 'end-1c')
        
        if not input_text:
            messagebox.showwarning("Warning", "Please enter some text")
            return
        
        # Create context
        context = ResponseContext(input_text=input_text)
        
        # Expand text
        expanded = self.engine.expand(input_text, context)
        
        # Display result
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert('1.0', expanded)
        
        self.status_bar.config(text=f"Text expanded successfully")
    
    def clear_text(self):
        """Clear input and output text"""
        self.input_text.delete('1.0', tk.END)
        self.output_text.delete('1.0', tk.END)
        self.status_bar.config(text="Cleared")
    
    def copy_result(self):
        """Copy expanded text to clipboard"""
        result = self.output_text.get('1.0', 'end-1c')
        if result:
            pyperclip.copy(result)
            self.status_bar.config(text="Copied to clipboard")
        else:
            messagebox.showwarning("Warning", "No text to copy")
    
    def add_rule(self):
        """Add a new shorthand rule"""
        trigger = self.trigger_entry.get()
        expansion = self.expansion_entry.get()
        
        if not trigger or not expansion:
            messagebox.showwarning("Warning", "Please enter both trigger and expansion")
            return
        
        rule = ShorthandRule(
            trigger=trigger,
            expansion=expansion,
            category=ResponseCategory.CUSTOM,
            trigger_type=TriggerType.EXACT
        )
        
        if self.engine.add_rule(rule):
            self.trigger_entry.delete(0, tk.END)
            self.expansion_entry.delete(0, tk.END)
            self.load_rules()
            self.status_bar.config(text=f"Rule added: {trigger}")
        else:
            messagebox.showerror("Error", "Failed to add rule")
    
    def load_rules(self):
        """Load and display all rules"""
        # Clear existing items
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
        
        # Add rules to tree
        for trigger, rule in self.engine.rules.items():
            self.rules_tree.insert('', 'end', values=(
                rule.trigger,
                rule.expansion[:50] + "..." if len(rule.expansion) > 50 else rule.expansion,
                rule.category.value,
                rule.usage_count
            ))
        
        self.status_bar.config(text=f"Loaded {len(self.engine.rules)} rules")
    
    def update_stats(self):
        """Update statistics display"""
        stats = self.engine.get_statistics()
        
        stats_text = "SHORTHAND SYSTEM STATISTICS\n"
        stats_text += "=" * 40 + "\n\n"
        
        stats_text += f"Total Rules: {stats['total_rules']}\n"
        stats_text += f"Total Templates: {stats['total_templates']}\n\n"
        
        stats_text += "Categories:\n"
        for category, count in stats['categories'].items():
            stats_text += f"  {category}: {count}\n"
        
        stats_text += f"\nCache Performance:\n"
        stats_text += f"  Hits: {stats['cache_performance']['hits']}\n"
        stats_text += f"  Misses: {stats['cache_performance']['misses']}\n"
        stats_text += f"  Hit Rate: {stats['cache_performance']['hit_rate']:.1%}\n"
        
        stats_text += f"\nResponse Times:\n"
        stats_text += f"  Average: {stats['response_times']['average']:.3f}s\n"
        stats_text += f"  Min: {stats['response_times']['min']:.3f}s\n"
        stats_text += f"  Max: {stats['response_times']['max']:.3f}s\n"
        
        if stats['top_rules']:
            stats_text += f"\nTop Used Rules:\n"
            for trigger, usage in stats['top_rules'][:5]:
                stats_text += f"  {trigger}: {usage} uses\n"
        
        self.stats_text.delete('1.0', tk.END)
        self.stats_text.insert('1.0', stats_text)
    
    def run(self):
        """Run the GUI application"""
        self.root.mainloop()


class ClipboardMonitor:
    """Monitor clipboard for automatic expansion"""
    
    def __init__(self, engine: ShorthandEngine):
        self.engine = engine
        self.last_clipboard = ""
        self.monitoring = False
        self.monitor_thread = None
    
    def start_monitoring(self):
        """Start monitoring clipboard"""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        print("Clipboard monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring clipboard"""
        self.monitoring = False
        print("Clipboard monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                current_clipboard = pyperclip.paste()
                
                if current_clipboard != self.last_clipboard:
                    # Check if clipboard contains shorthand
                    expanded = self.engine.expand(current_clipboard)
                    
                    if expanded != current_clipboard:
                        # Update clipboard with expanded text
                        pyperclip.copy(expanded)
                        print(f"Expanded: '{current_clipboard}' -> '{expanded}'")
                    
                    self.last_clipboard = expanded
                
                time.sleep(0.5)  # Check every 500ms
                
            except Exception as e:
                print(f"Clipboard monitor error: {e}")
                time.sleep(1)


class HotkeyExpander:
    """Global hotkey expansion system"""
    
    def __init__(self, engine: ShorthandEngine):
        self.engine = engine
        self.enabled = False
        self.hotkey = 'ctrl+space'  # Default expansion hotkey
    
    def enable(self):
        """Enable hotkey expansion"""
        keyboard.add_hotkey(self.hotkey, self.expand_current)
        self.enabled = True
        print(f"Hotkey expansion enabled ({self.hotkey})")
    
    def disable(self):
        """Disable hotkey expansion"""
        keyboard.remove_hotkey(self.hotkey)
        self.enabled = False
        print("Hotkey expansion disabled")
    
    def expand_current(self):
        """Expand current selection or word"""
        try:
            # Copy current selection
            keyboard.press_and_release('ctrl+c')
            time.sleep(0.1)
            
            # Get clipboard content
            text = pyperclip.paste()
            
            # Expand text
            expanded = self.engine.expand(text)
            
            if expanded != text:
                # Replace with expanded text
                pyperclip.copy(expanded)
                keyboard.press_and_release('ctrl+v')
                print(f"Expanded: '{text}' -> '{expanded}'")
            
        except Exception as e:
            print(f"Hotkey expansion error: {e}")


class EmailIntegration:
    """Email client integration for auto-responses"""
    
    def __init__(self, engine: ShorthandEngine):
        self.engine = engine
        load_library("email", self.engine)
        load_library("customer_service", self.engine)
    
    def process_email(self, subject: str, body: str, sender: str) -> str:
        """Process email and generate response"""
        # Create context
        context = ResponseContext(
            input_text=body,
            sender=sender,
            channel="email",
            metadata={
                "subject": subject,
                "sender_name": sender.split('@')[0].title()
            }
        )
        
        # Analyze email sentiment
        if any(word in body.lower() for word in ['urgent', 'asap', 'immediately']):
            context.urgency = 8
        
        # Generate response
        response = self.engine.expand(body, context)
        
        # If no expansion, suggest templates
        if response == body:
            suggestions = self.engine.suggest_responses(context, num_suggestions=1)
            if suggestions:
                response = suggestions[0][0]
        
        return response
    
    def create_email_signature(self, name: str, title: str, company: str) -> ShorthandRule:
        """Create personalized email signature"""
        signature = f"\n\nBest regards,\n{name}\n{title}\n{company}"
        
        rule = ShorthandRule(
            trigger="sig",
            expansion=signature,
            category=ResponseCategory.EMAIL,
            trigger_type=TriggerType.EXACT,
            priority=10
        )
        
        self.engine.add_rule(rule)
        return rule


class ChatbotIntegration:
    """Chatbot integration for customer support"""
    
    def __init__(self, engine: ShorthandEngine):
        self.engine = engine
        load_library("customer_service", self.engine)
        load_library("it_support", self.engine)
        self.conversation_history = []
    
    def process_message(self, message: str, user_id: str) -> str:
        """Process chat message and generate response"""
        # Add to history
        self.conversation_history.append({"user": user_id, "message": message})
        
        # Create context with history
        context = ResponseContext(
            input_text=message,
            sender=user_id,
            channel="chat",
            history=[h["message"] for h in self.conversation_history[-5:]],
            metadata={"user_id": user_id}
        )
        
        # Generate response
        response = self.engine.expand(message, context)
        
        # If no expansion, use auto-responder
        if response == message:
            responder = AutoResponder(self.engine)
            response = responder.generate_response(message, context)
        
        # Add response to history
        self.conversation_history.append({"bot": "assistant", "message": response})
        
        return response


def demo_integrations():
    """Demonstrate various integrations"""
    print("="*60)
    print("SHORTHAND AUTO-RESPONSE INTEGRATIONS DEMO")
    print("="*60)
    
    engine = ShorthandEngine()
    
    # 1. Email Integration
    print("\n[1] Email Integration:")
    email_int = EmailIntegration(engine)
    email_int.create_email_signature("John Doe", "Senior Developer", "Tech Corp")
    
    test_email = "Can you help with this urgent issue? sig"
    response = email_int.process_email(
        subject="Urgent Help Needed",
        body=test_email,
        sender="client@example.com"
    )
    print(f"  Email: '{test_email}'")
    print(f"  Response: '{response}'")
    
    # 2. Chatbot Integration
    print("\n[2] Chatbot Integration:")
    chatbot = ChatbotIntegration(engine)
    
    messages = [
        "Hello, I need help",
        "My computer won't start",
        "ty for your help"
    ]
    
    for msg in messages:
        response = chatbot.process_message(msg, "user123")
        print(f"  User: '{msg}'")
        print(f"  Bot: '{response}'")
    
    # 3. Clipboard Monitor
    print("\n[3] Clipboard Monitor:")
    monitor = ClipboardMonitor(engine)
    print("  Monitor initialized (not started)")
    
    # 4. Hotkey Expander
    print("\n[4] Hotkey Expander:")
    hotkey = HotkeyExpander(engine)
    print("  Hotkey system initialized (not enabled)")
    
    print("\n" + "="*60)
    print("Integration examples completed!")
    print("To run the GUI: python shorthand_integrations.py --gui")
    print("="*60)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
        # Run GUI application
        app = ShorthandGUI()
        app.run()
    else:
        # Run demo
        demo_integrations()