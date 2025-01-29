# Core imports
import os
import time
import re
import json
from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import CodeUnit
from java.lang import Thread
from javax.swing import (
    JFrame, JPanel, JLabel, JTextField, JButton, BorderFactory, 
    JScrollPane, SwingConstants, JList, DefaultListModel,
    ListCellRenderer, JPopupMenu, JMenuItem, JTabbedPane
)
from java.awt import BorderLayout, GridLayout, Color, Font, Dimension
from javax.swing.border import EmptyBorder
from java.awt.event import MouseAdapter, MouseEvent
from javax.swing.event import ListSelectionListener
from javax.swing.plaf.basic import BasicTabbedPaneUI

# Constants
TEMP_DIR = "C:\\temp\\windbg"
FONT_FAMILY = "Consolas"
DARK_BG = Color(20, 20, 20)
DARKER_BG = Color.BLACK
LIGHTER_BG = Color(40, 40, 40)
BORDER_COLOR = Color(60, 60, 60)
TEXT_COLOR = Color.WHITE
DIM_TEXT = Color(160, 160, 160)
HIGHLIGHT_COLOR = Color(135, 206, 250)

def parse_immediate(imm_str):
    """Parse immediate value, handling hex and decimal."""
    try:
        return int(imm_str[2:], 16) if imm_str.startswith('0x') else int(imm_str)
    except:
        return None
    
def create_scroll_pane(component):
    """Creates a standardized scroll pane."""
    scroll_pane = JScrollPane(component)
    scroll_pane.setBorder(BorderFactory.createLineBorder(BORDER_COLOR))
    scroll_pane.getViewport().setBackground(DARK_BG)
    return scroll_pane

def create_title_label(text):
    """Creates a standardized title label."""
    label = JLabel(text)
    label.setFont(Font(FONT_FAMILY, Font.BOLD, 12))
    label.setForeground(TEXT_COLOR)
    label.setBorder(EmptyBorder(0, 0, 2, 0))
    return label

def wait_for_file_unlock(filepath, timeout=1.0, check_closing=True):
    """
    Waits for a file to be completely written and unlocked.
    Returns True if file is ready, False if timeout occurred.
    """
    start_time = time.time()
    last_size = -1
    stable_count = 0
    
    # Special handling for stack file with longer timeout
    is_stack_file = filepath.endswith("stack.txt")
    if is_stack_file:
        stack_timeout = 3.0  # Longer timeout for stack file
        while time.time() - start_time < stack_timeout:
            try:
                if os.path.exists(filepath):
                    current_size = os.path.getsize(filepath)
                    
                    # If size hasn't changed for a bit, check content
                    if current_size == last_size:
                        stable_count += 1
                        if stable_count >= 3:  # Wait for more stability
                            with open(filepath, 'r') as f:
                                content = f.read().strip()
                                # Look for either closing message or complete stack
                                if "Closing open log file" in content or "\n #" in content:
                                    return True
                    else:
                        stable_count = 0
                        last_size = current_size
            except:
                pass
            time.sleep(0.05)  # Slightly longer sleep for stack file
        return False
    
    # Regular file handling for other files
    while time.time() - start_time < timeout:
        try:
            current_size = os.path.getsize(filepath)
            
            if current_size == last_size:
                stable_count += 1
                if stable_count >= 2:
                    with open(filepath, 'r') as f:
                        content = f.read()
                        if not check_closing:
                            return bool(content.strip())
                        return "Closing open log file" in content
            else:
                stable_count = 0
                last_size = current_size
                
        except (IOError, OSError):
            stable_count = 0
        
        time.sleep(0.02)
    
    return False

def get_windbg_command():
    """Return the WinDbg command that needs to be entered after every command."""
    return "$$>a< %s" % os.path.join(TEMP_DIR, "cmd.txt")

def print_startup_message():
    """Print the startup message with WinDbg command information."""
    print("=" * 80)
    print("WinDbg Sync Script - Startup Instructions")
    print("=" * 80)
    print("\nAfter every WinDbg command, you need to run the following command:")
    print("\n    " + get_windbg_command())
    print("\nThis will update the sync state and refresh the Ghidra view.")
    print("=" * 80 + "\n")

class HistoryEntry:
    """Represents a single entry in the execution history."""
    def __init__(self, address, instruction, registers):
        self.address = address
        self.instruction = instruction
        self.registers = registers
        self.timestamp = time.time()

class CustomCellRenderer(JLabel, ListCellRenderer):
    """Base class for custom cell renderers."""
    def __init__(self, font_size=11):
        self.setFont(Font(FONT_FAMILY, Font.PLAIN, font_size))
        self.setOpaque(True)
    
    def set_selection_colors(self, is_selected):
        if is_selected:
            self.setForeground(TEXT_COLOR)
            self.setBackground(LIGHTER_BG)
        else:
            self.setForeground(DIM_TEXT)
            self.setBackground(DARK_BG)

class HistoryCellRenderer(CustomCellRenderer):
    """Cell renderer for history list items."""
    def getListCellRendererComponent(self, list, value, index, isSelected, cellHasFocus):
        timestamp = time.strftime("%H:%M:%S", time.localtime(value.timestamp))
        self.setText("[%s] 0x%x: %s" % (timestamp, value.address, value.instruction))
        self.set_selection_colors(isSelected)
        return self

class BreakpointCellRenderer(CustomCellRenderer):
    """Cell renderer for breakpoint list items."""
    def getListCellRendererComponent(self, list, value, index, isSelected, cellHasFocus):
        self.setText(value['text'])
        # Set colors based on enabled/disabled status
        self.setForeground(Color(160, 255, 160) if value['status'] == 'e' else Color(255, 160, 160))
        self.setBackground(LIGHTER_BG if isSelected else DARK_BG)
        return self

class HistoryPanel(JPanel):
    """Panel for displaying execution history."""
    def __init__(self, callback=None):
        super(HistoryPanel, self).__init__()
        self.callback = callback
        self.history = []
        self.setup_ui()
        
    def setup_ui(self):
        self.setLayout(BorderLayout(0, 0))
        self.setBackground(DARKER_BG)
        self.setBorder(EmptyBorder(5, 5, 5, 5))

        self.add(create_title_label("Execution History"), BorderLayout.NORTH)

        # List model and JList for history
        self.list_model = DefaultListModel()
        self.history_list = JList(self.list_model)
        self.history_list.setBackground(DARK_BG)
        self.history_list.setCellRenderer(HistoryCellRenderer())

        # Add selection listener - Fixed implementation
        class SelectionAdapter(ListSelectionListener):
            def __init__(self, outer_callback):
                self.outer_callback = outer_callback
                
            def valueChanged(self, e):
                if not e.getValueIsAdjusting():  # Only process when selection is final
                    selected = e.getSource().getSelectedValue()
                    if selected and self.outer_callback:
                        self.outer_callback(selected)

        # Properly wire up the selection listener with the callback
        self.history_list.addListSelectionListener(
            SelectionAdapter(self.callback)
        )

        self.add(create_scroll_pane(self.history_list), BorderLayout.CENTER)
    
    def add_entry(self, address, instruction, registers):
        """Add a new history entry."""
        entry = HistoryEntry(address, instruction, registers)
        self.history.append(entry)
        self.list_model.insertElementAt(entry, 0)  # Add to top of list
        
        # Limit history size to 1000 entries
        while len(self.history) > 1000:
            self.history.pop(0)
            self.list_model.remove(self.list_model.size() - 1)

class BreakpointPanel(JPanel):
    """Panel for managing breakpoints."""
    def __init__(self, sync_script):
        super(BreakpointPanel, self).__init__()
        self.sync_script = sync_script
        self.setup_ui()
        
    def setup_ui(self):
        self.setLayout(BorderLayout(0, 0))
        self.setBackground(DARKER_BG)
        self.setBorder(EmptyBorder(5, 5, 5, 5))
        
        self.add(create_title_label("Breakpoints"), BorderLayout.NORTH)
        
        # List setup
        self.list_model = DefaultListModel()
        self.breakpoint_list = JList(self.list_model)
        self.breakpoint_list.setBackground(DARK_BG)
        self.breakpoint_list.setCellRenderer(BreakpointCellRenderer())
        
        # Popup menu setup
        self.setup_popup_menu()
        
        # Mouse listener for popup
        class PopupListener(MouseAdapter):
            def mousePressed(this, e):
                if e.isPopupTrigger():
                    self.show_popup(e)
            def mouseReleased(this, e):
                if e.isPopupTrigger():
                    self.show_popup(e)
        
        self.breakpoint_list.addMouseListener(PopupListener())
        self.add(create_scroll_pane(self.breakpoint_list), BorderLayout.CENTER)
        self.setPreferredSize(Dimension(400, 200))
    
    def setup_popup_menu(self):
        """Setup the popup menu for breakpoint actions."""
        self.popup = JPopupMenu()
        menu_items = [
            ("Add Breakpoint Here", self.add_breakpoint),
            ("Enable", self.enable_breakpoint),
            ("Disable", self.disable_breakpoint),
            ("Delete", self.delete_breakpoint)
        ]
        
        for text, action in menu_items:
            item = JMenuItem(text)
            item.addActionListener(action)
            self.popup.add(item)
    
    def show_popup(self, event):
        self.popup.show(event.getComponent(), event.getX(), event.getY())
    
    def add_breakpoint(self, event):
        """Add a breakpoint at current address."""
        current_addr = self.sync_script.get_current_address()
        if current_addr:
            kernel_addr = current_addr + self.sync_script.kernel_base - self.sync_script.getCurrentProgram().getImageBase().getOffset()
            addr_str = "%x`%x" % (kernel_addr >> 32, kernel_addr & 0xFFFFFFFF)
            self.sync_script.write_command("bp %s" % addr_str)
    
    def enable_breakpoint(self, event):
        """Enable selected breakpoint."""
        selected = self.breakpoint_list.getSelectedValue()
        if selected:
            self.sync_script.write_command("be %s" % selected['id'])
    
    def disable_breakpoint(self, event):
        """Disable selected breakpoint."""
        selected = self.breakpoint_list.getSelectedValue()
        if selected:
            self.sync_script.write_command("bd %s" % selected['id'])
    
    def delete_breakpoint(self, event):
        """Delete selected breakpoint."""
        selected = self.breakpoint_list.getSelectedValue()
        if selected:
            self.sync_script.write_command("bc %s" % selected['id'])
    
    def update_breakpoints(self, breakpoints):
        """Update the breakpoint list display."""
        self.list_model.clear()
        for bp in breakpoints:
            item = {
                'id': bp['id'],
                'text': "%s: %s" % (bp['address'], bp['description']),
                'status': bp['status']
            }
            self.list_model.addElement(item)

class InstructionPanel(JPanel):
    """Panel to display previous, current, and next instructions."""
    def __init__(self):
        super(InstructionPanel, self).__init__()
        self.setup_ui()
    
    def setup_ui(self):
        self.setLayout(BorderLayout(0, 5))
        self.setBackground(Color(30, 30, 30))
        self.setBorder(EmptyBorder(2, 5, 2, 5))
        
        # Create instruction labels
        instructions_panel = JPanel(GridLayout(3, 1, 2, 2))
        instructions_panel.setBackground(Color(30, 30, 30))
        
        self.prev_instruction = self.create_instruction_label("Previous: ", dim=True)
        self.current_instruction = self.create_instruction_label("Current: ", bold=True)
        self.next_instruction = self.create_instruction_label("Next: ", dim=True)
        
        for label in (self.prev_instruction, self.current_instruction, self.next_instruction):
            instructions_panel.add(label)
        
        self.add(instructions_panel, BorderLayout.CENTER)
    
    def create_instruction_label(self, prefix, dim=False, bold=False):
        """Create a standardized instruction label."""
        label = JLabel(prefix)
        label.setFont(Font(FONT_FAMILY, Font.BOLD if bold else Font.PLAIN, 11))
        label.setForeground(DIM_TEXT if dim else TEXT_COLOR)
        return label
    
    def update_instructions(self, prev_inst, curr_inst, next_inst):
        """Update all three instruction labels."""
        self.prev_instruction.setText("Previous: " + (prev_inst or "<none>"))
        self.current_instruction.setText("Current: " + (curr_inst or "<none>"))
        self.next_instruction.setText("Next: " + (next_inst or "<none>"))

class StackTracePanel(JPanel):
    """Panel for displaying the call stack."""
    def __init__(self):
        super(StackTracePanel, self).__init__()
        self.setup_ui()
    
    def setup_ui(self):
        self.setLayout(BorderLayout(0, 0))
        self.setBackground(DARKER_BG)
        self.setBorder(EmptyBorder(5, 5, 5, 5))
        
        self.add(create_title_label("Call Stack"), BorderLayout.NORTH)
        
        # Stack entries panel with minimal spacing
        self.entries_panel = JPanel(GridLayout(0, 1, 0, -1))
        self.entries_panel.setBackground(DARKER_BG)
        
        scroll_pane = create_scroll_pane(self.entries_panel)
        scroll_pane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        scroll_pane.setBorder(BorderFactory.createEmptyBorder())
        
        self.add(scroll_pane, BorderLayout.CENTER)
        self.setPreferredSize(Dimension(400, 200))
    
    def create_stack_entry(self, index, addr, symbol):
        """Create a single stack entry panel with optimized layout."""
        entry = JPanel(BorderLayout(5, 0))
        entry.setBackground(DARK_BG)
        entry.setBorder(EmptyBorder(0, 4, 0, 4))
        entry.setPreferredSize(Dimension(entry.getPreferredSize().width, 16))
        
        # Create and configure labels
        labels = {
            'index': (("%02d" % index), Font.PLAIN, Color.GRAY),
            'addr': (addr, Font.PLAIN, HIGHLIGHT_COLOR),
            'symbol': (symbol, Font.PLAIN, TEXT_COLOR)
        }
        
        label_components = {}
        for key, (text, style, color) in labels.items():
            label = JLabel(text)
            label.setFont(Font(FONT_FAMILY, style, 11))
            label.setForeground(color)
            label_components[key] = label
        
        # Layout the components
        addr_panel = JPanel(BorderLayout(2, 0))
        addr_panel.setBackground(DARK_BG)
        addr_panel.setBorder(EmptyBorder(0, 0, 0, 0))
        addr_panel.add(label_components['index'], BorderLayout.WEST)
        addr_panel.add(label_components['addr'], BorderLayout.CENTER)
        
        entry.add(addr_panel, BorderLayout.WEST)
        entry.add(label_components['symbol'], BorderLayout.CENTER)
        
        return entry
    
    def parse_stack_line(self, line):
        """Parse a stack trace line with improved error handling."""
        try:
            pattern = r'(\d+)\s+([\w`]+)\s+([\w`]+)\s+(.+)'
            match = re.match(pattern, line)
            
            if not match:
                return None
                
            return {
                'index': int(match.group(1)),
                'child_sp': match.group(2).replace('`', ''),
                'ret_addr': match.group(3).replace('`', ''),
                'call_site': match.group(4).strip()
            }
            
        except Exception as e:
            print("Error parsing stack line: %s\nLine: %s" % (str(e), line))
            return None
    
    def update_stack(self, stack_file):
        """Update the stack trace display with improved file handling."""
        if not os.path.exists(stack_file):
            return
                
        # Wait longer for stack file and ensure it's complete
        if not wait_for_file_unlock(stack_file, timeout=5.0):
            # print("Stack file not ready yet")
            return
                
        try:
            self.entries_panel.removeAll()
            
            with open(stack_file, 'r') as f:
                lines = f.readlines()
            
            valid_entries = 0
            for line in lines:
                # Skip metadata lines
                if any(line.startswith(x) for x in ('Opened log file', 'Closing', ' #')) or not line.strip():
                    continue
                
                entry = self.parse_stack_line(line)
                if entry:
                    panel = self.create_stack_entry(
                        entry['index'],
                        entry['ret_addr'],
                        entry['call_site']
                    )
                    self.entries_panel.add(panel)
                    valid_entries += 1
            
            # Only update display if we got some valid entries
            if valid_entries > 0:
                self.entries_panel.revalidate()
                self.entries_panel.repaint()
            
        except Exception as e:
            print("Error updating stack trace: %s" % str(e))

class RegisterPanel(JPanel):
    """Panel for displaying register values with change tracking."""
    def __init__(self, name, initial_value="0000000000000000"):
        super(RegisterPanel, self).__init__()
        self.name = name
        self.setup_ui(initial_value)
    
    def setup_ui(self, initial_value):
        self.setLayout(BorderLayout(0, 0))
        self.setBorder(EmptyBorder(0, 2, 0, 2))
        self.setBackground(DARKER_BG)
        
        # Create main value display
        self.line_panel = JPanel(BorderLayout(4, 0))
        self.line_panel.setBackground(DARKER_BG)
        
        # Create and configure labels
        self.label = self.create_label(self.name.ljust(4), Font.PLAIN, TEXT_COLOR)
        self.value = self.create_label(initial_value, Font.PLAIN, HIGHLIGHT_COLOR)
        self.extra_value = self.create_label("", Font.ITALIC, Color.GRAY)
        
        # Layout components
        self.line_panel.add(self.label, BorderLayout.WEST)
        self.line_panel.add(self.value, BorderLayout.CENTER)
        
        self.add(self.line_panel, BorderLayout.NORTH)
        self.add(self.extra_value, BorderLayout.CENTER)
        
        self.setPreferredSize(Dimension(200, 30))
    
    def create_label(self, text, style, color):
        """Create a standardized label with given properties."""
        label = JLabel(text, SwingConstants.LEFT)
        label.setFont(Font(FONT_FAMILY, style, 12))
        label.setForeground(color)
        return label
    
    def update_value(self, new_value, changed=False, will_change=False, future_value=None):
        """Update register value with change indication."""
        colors = {
            'changed': (Color(255, 160, 160), Color(200, 100, 100)),  # Bright red, Light red
            'will_change': (Color(160, 255, 160), Color(100, 200, 100)),  # Bright green, Light green
            'normal': (HIGHLIGHT_COLOR, None)  # Default blue
        }
        
        if changed:
            value_color, extra_color = colors['changed']
            self.extra_value.setText("prev: " + self.value.getText())
        elif will_change and future_value:
            value_color, extra_color = colors['will_change']
            self.extra_value.setText("next: " + future_value)
        else:
            value_color, extra_color = colors['normal']
            self.extra_value.setText("")
        
        self.value.setForeground(value_color)
        if extra_color:
            self.extra_value.setForeground(extra_color)
        
        self.value.setText(new_value)

class DebuggerGUI(JFrame):
    """Main debugger GUI window."""
    def __init__(self, kernel_base, sync_script):
        super(DebuggerGUI, self).__init__("GhidraDbg")
        self.kernel_base = kernel_base
        self.sync_script = sync_script
        self.previous_values = {}
        self.register_panels = {}
        self.instruction_history = []
        self.max_history = 100
        self.viewing_historical = False
        
        self.setup_ui()
    
    def setup_ui(self):
        """Initialize the GUI layout."""
        # Create tabbed pane
        self.tabbed_pane = self.create_tabbed_pane()
        
        # Create panel instances with defined order
        def history_callback(entry):
            if entry:
                self.update_registers({"registers": entry.registers}, entry.instruction, historical=True)
                self.sync_script.go_to_address(entry.address)
        
        # Define panels in desired order
        panels = [
            ("Registers", self.create_main_panel()),
            ("Call Stack", StackTracePanel()),
            ("History", HistoryPanel(history_callback)),
            ("Breakpoints", BreakpointPanel(self.sync_script))
        ]
        
        # Store references to frequently used panels
        for title, panel in panels:
            if title == "Call Stack":
                self.stack_panel = panel
            elif title == "Breakpoints":
                self.breakpoint_panel = panel
            elif title == "History":
                self.history_panel = panel
        
        # Add all tabs in the specified order
        for title, panel in panels:
            self.tabbed_pane.addTab(title, panel)
            tab_index = self.tabbed_pane.getTabCount() - 1
            self.tabbed_pane.setBackgroundAt(tab_index, LIGHTER_BG)
            self.tabbed_pane.setForegroundAt(tab_index, TEXT_COLOR)
        
        self.setContentPane(self.tabbed_pane)
        self.setSize(450, 500)
        self.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
        self.setLocationRelativeTo(None)
    
    def create_tabbed_pane(self):
        """Create and configure the tabbed pane with custom styling."""
        class DarkTabbedPaneUI(BasicTabbedPaneUI):
            def installDefaults(self):
                super(DarkTabbedPaneUI, self).installDefaults()
                self.shadow = DARK_BG
                self.darkShadow = DARK_BG
                self.highlight = LIGHTER_BG
                self.lightHighlight = LIGHTER_BG
            
            def paintTabBackground(self, g, tabPlacement, tabIndex, x, y, w, h, isSelected):
                g.setColor(LIGHTER_BG if isSelected else Color(30, 30, 30))
                g.fillRect(x, y, w, h)
        
        tabbed_pane = JTabbedPane()
        tabbed_pane.setBackground(DARKER_BG)
        tabbed_pane.setForeground(TEXT_COLOR)
        tabbed_pane.setFont(Font(FONT_FAMILY, Font.PLAIN, 11))
        tabbed_pane.setUI(DarkTabbedPaneUI())
        tabbed_pane.setBorder(EmptyBorder(0, 0, 0, 0))
        
        return tabbed_pane
    
    def create_main_panel(self):
        """Create the main register display panel."""
        main_panel = JPanel(BorderLayout(0, 5))
        main_panel.setBackground(DARKER_BG)
        main_panel.setBorder(EmptyBorder(5, 5, 5, 5))
        
        # Status and instruction panel
        top_panel = self.create_top_panel()
        main_panel.add(top_panel, BorderLayout.CENTER)
        
        # Register panels
        register_panel = self.create_register_panel()
        segment_panel = self.create_segment_panel()
        
        # Add register panels to top panel
        top_panel.add(register_panel, BorderLayout.CENTER)
        top_panel.add(segment_panel, BorderLayout.SOUTH)
        
        return main_panel
    
    def create_top_panel(self):
        """Create the top section with status and instructions."""
        top_panel = JPanel(BorderLayout(0, 5))
        top_panel.setBackground(DARKER_BG)
        
        # Status panel
        status_panel = JPanel(GridLayout(3, 1, 2, 2)) 
        status_panel.setBackground(Color(30, 30, 30))
        status_panel.setBorder(EmptyBorder(2, 5, 2, 5))
        
        self.status_label = self.create_info_label("Waiting for updates...")
        self.function_label = self.create_info_label("Function: ", highlight=True)
        
        # Create new label for kernel base
        kernel_base_str = "Kernel Base: 0x%x" % self.kernel_base
        self.kernel_base_label = self.create_info_label(kernel_base_str, highlight=False)
        
        status_panel.add(self.status_label)
        status_panel.add(self.function_label)
        status_panel.add(self.kernel_base_label)
        
        # Create instruction panel
        self.instruction_panel = InstructionPanel()
        
        # Combine status and instruction panels
        top_status = JPanel(BorderLayout(0, 5))
        top_status.setBackground(DARKER_BG)
        top_status.add(status_panel, BorderLayout.NORTH)
        top_status.add(self.instruction_panel, BorderLayout.CENTER)
        
        top_panel.add(top_status, BorderLayout.NORTH)
        return top_panel
    
    def create_info_label(self, text, highlight=False):
        """Create a standardized info label."""
        label = JLabel(text)
        label.setFont(Font(FONT_FAMILY, Font.PLAIN, 11))
        label.setForeground(HIGHLIGHT_COLOR if highlight else DIM_TEXT)
        return label
    
    def create_register_panel(self):
        """Create the general purpose registers panel."""
        register_panel = JPanel(GridLayout(0, 2, 10, 0))
        register_panel.setBackground(DARKER_BG)
        
        registers = [
            'rax', 'r8', 'rbx', 'r9', 'rcx', 'r10', 
            'rdx', 'r11', 'rsi', 'r12', 'rdi', 'r13',
            'rbp', 'r14', 'rsp', 'r15', 'rip', 'efl'
        ]
        
        for reg in registers:
            panel = RegisterPanel(reg.upper())
            self.register_panels[reg] = panel
            register_panel.add(panel)
        
        return register_panel
    
    def create_segment_panel(self):
        """Create the segment registers panel."""
        seg_panel = JPanel(GridLayout(1, 6, 4, 0))
        seg_panel.setBackground(DARKER_BG)
        
        segments = ['cs', 'ds', 'es', 'fs', 'gs', 'ss']
        for seg in segments:
            panel = RegisterPanel(seg.upper())
            panel.setPreferredSize(Dimension(60, 30))
            self.register_panels[seg] = panel
            seg_panel.add(panel)
        
        return seg_panel
    
    def set_instruction(self, instruction, function_name=None, current_program=None, current_addr=None):
        """Update the instruction and function display with adjacent instructions."""
        # Clear historical view when new instruction comes in
        self.viewing_historical = False
        if function_name:
            self.function_label.setText("Function: " + function_name)
        else:
            self.function_label.setText("Function: <unknown>")
        
        # Get previous and next instructions
        prev_inst, next_inst = None, None
        if instruction:
            # Add current instruction to history if it's new
            current_entry = (current_addr, instruction) if current_addr else (None, instruction)
            if not self.instruction_history or current_entry != self.instruction_history[-1]:
                self.instruction_history.append(current_entry)
                # Trim history if it exceeds max size
                if len(self.instruction_history) > self.max_history:
                    self.instruction_history.pop(0)
            
            # Get previous instruction from history
            if len(self.instruction_history) > 1:
                prev_inst = self.instruction_history[-2][1]
            
            # Get next instruction based on current instruction type
            if current_program and current_addr:
                try:
                    # Get the instruction object
                    instruction_obj = current_program.getListing().getInstructionAt(current_addr)
                    if instruction_obj:
                        # Get flow type and reference types
                        flow_type = instruction_obj.getFlowType()
                        refs = instruction_obj.getReferencesFrom()
                        
                        # Check if it's a branching instruction
                        if flow_type.isJump() or flow_type.isCall():
                            # For conditional jumps, show both paths
                            if flow_type.isConditional():
                                fallthrough = instruction_obj.getFallThrough()
                                if refs and len(refs) > 0:
                                    target = refs[0].getToAddress()
                                    fall_inst = current_program.getListing().getInstructionAt(fallthrough)
                                    target_inst = current_program.getListing().getInstructionAt(target)
                                    
                                    if fall_inst and target_inst:
                                        next_inst = "if: %s, else: %s" % (target_inst, fall_inst)
                                    elif fall_inst:
                                        next_inst = "if: ?, else: %s" % fall_inst
                                    elif target_inst:
                                        next_inst = "if: %s, else: ?" % target_inst
                            # For unconditional jumps/calls, show target
                            elif refs and len(refs) > 0:
                                target = refs[0].getToAddress()
                                target_inst = current_program.getListing().getInstructionAt(target)
                                if target_inst:
                                    next_inst = str(target_inst)
                        # For normal flow, get next instruction
                        else:
                            fallthrough = instruction_obj.getFallThrough()
                            if fallthrough:
                                next_inst_obj = current_program.getListing().getInstructionAt(fallthrough)
                                if next_inst_obj:
                                    next_inst = str(next_inst_obj)
                
                except Exception as e:
                    print("Error getting next instruction:", str(e))
        
        # Update instruction panel
        self.instruction_panel.update_instructions(prev_inst, instruction, next_inst)

    def analyze_instruction(self, instruction, registers):
        """Analyze instruction to predict register changes."""
        future_values = {}
        will_change = set()
        
        try:
            inst_lower = instruction.lower()
            parts = inst_lower.split(None, 1)
            if len(parts) != 2:
                return future_values
            
            opcode, operands_str = parts
            operands = [op.strip() for op in operands_str.split(',')]
            
            # Instruction analysis based on opcode
            if opcode in ['mov', 'movzx', 'movsx']:
                self._handle_mov_instruction(operands, registers, future_values, will_change)
            elif opcode in ['add', 'sub', 'and', 'or', 'xor']:
                self._handle_arithmetic_instruction(opcode, operands, registers, future_values, will_change)
            elif opcode == 'xchg':
                self._handle_xchg_instruction(operands, registers, future_values, will_change)
            elif opcode in ['inc', 'dec']:
                self._handle_inc_dec_instruction(opcode, operands, registers, future_values, will_change)
            elif opcode in ['push', 'pop']:
                self._handle_stack_instruction(opcode, operands, registers, future_values, will_change)
            elif opcode in ['mul', 'imul', 'div', 'idiv']:
                self._handle_math_instruction(future_values, will_change)
            elif opcode in ['call', 'ret', 'retn']:
                self._handle_control_flow_instruction(opcode, registers, future_values, will_change)
        
        except Exception as e:
            print("Error analyzing instruction:", str(e))
        
        return future_values
    
    # Helper functions
    def get_dest_register(operand):
        """Extract register from operand, handling memory references."""
        cleaned = re.sub(r'(?:qword|dword|word|byte)\s+ptr\s+', '', operand).strip()
        return None if cleaned.startswith('[') and cleaned.endswith(']') else cleaned
    
    def calculate_arithmetic(self, reg_value, operation, imm_value):
        """Calculate arithmetic result with overflow handling."""
        try:
            reg_val = int(reg_value, 16)
            ops = {
                'add': lambda x, y: x + y,
                'sub': lambda x, y: x - y,
                'and': lambda x, y: x & y,
                'or':  lambda x, y: x | y,
                'xor': lambda x, y: x ^ y
            }
            result = ops[operation](reg_val, imm_value) & ((1 << 64) - 1)
            return "%016x" % result
        except:
            return "???"
        
    def _get_dest_register(self, operand):
        """Extract register from operand, handling memory references."""
        cleaned = re.sub(r'(?:qword|dword|word|byte)\s+ptr\s+', '', operand).strip()
        return None if cleaned.startswith('[') and cleaned.endswith(']') else cleaned
    
    def update_stack(self, stack_file):
        """Update stack information."""
        if hasattr(self, 'stack_panel'):
            self.stack_panel.update_stack(stack_file)

    def update_breakpoints(self, breakpoints):
        """Update breakpoint information."""
        if hasattr(self, 'breakpoint_panel'):
            self.breakpoint_panel.update_breakpoints(breakpoints)
    
    def update_registers(self, state, instruction=None, historical=False):
        """Update the register display."""
        try:
            # Update historical view tracking
            self.viewing_historical = historical
            
            future_values = {}
            if instruction:  # Removed historical check here
                future_values = self.analyze_instruction(instruction, state['registers'])
            
            if 'registers' in state:
                regs = state['registers']
                if 'rip' in state:
                    regs['rip'] = state['rip']
                for reg_name, value in regs.items():
                    if reg_name in self.register_panels:
                        changed = False
                        will_change = False
                        future_value = None
                        
                        # Always check for changes and future values
                        if reg_name in self.previous_values:
                            if value != self.previous_values[reg_name]:
                                changed = True
                        
                        if reg_name in future_values:
                            will_change = True
                            future_value = future_values[reg_name]
                        
                        self.register_panels[reg_name].update_value(
                            value,
                            changed=changed,
                            will_change=will_change,
                            future_value=future_value
                        )
                        if not historical:  # Only update previous values if not in historical view
                            self.previous_values[reg_name] = value
            
            if 'segments' in state:
                segs = state['segments']
                for seg_name, value in segs.items():
                    if seg_name in self.register_panels:
                        self.register_panels[seg_name].update_value(value)
            
            if 'rip' in state:
                if historical:
                    self.status_label.setText("RIP: " + state['rip'] + " (Historical View)")
                else:
                    self.status_label.setText("RIP: " + state['rip'])
            
            # Add to history if not viewing historical data
            if not historical and instruction and 'registers' in state:
                try:
                    addr = int(state['rip'], 16)
                    self.history_panel.add_entry(addr, instruction, state['registers'].copy())
                except:
                    pass
        
        except Exception as e:
            print("Error updating GUI:", str(e))

    def _handle_mov_instruction(self, operands, registers, future_values, will_change):
        """Handle MOV and similar instructions."""
        if len(operands) == 2:
            dest = self._get_dest_register(operands[0])
            if dest:
                will_change.add(dest)
                if operands[1] in registers:
                    future_values[dest] = registers[operands[1]]
                elif operands[1].startswith('0x'):
                    future_values[dest] = operands[1][2:].zfill(16)
                else:
                    future_values[dest] = "???"

    def _handle_arithmetic_instruction(self, opcode, operands, registers, future_values, will_change):
        """Handle arithmetic instructions."""
        if len(operands) == 2:
            dest = self._get_dest_register(operands[0])
            imm_val = parse_immediate(operands[1])
            
            if dest and dest in registers and imm_val is not None:
                will_change.add(dest)
                future_values[dest] = self.calculate_arithmetic(registers[dest], opcode, imm_val)
            elif dest:
                will_change.add(dest)
                future_values[dest] = "???"

    def _handle_xchg_instruction(self, operands, registers, future_values, will_change):
        """Handle XCHG instruction."""
        if len(operands) == 2:
            reg1, reg2 = map(self._get_dest_register, operands)
            if reg1 and reg2 and reg1 in registers and reg2 in registers:
                will_change.update([reg1, reg2])
                future_values[reg1] = registers[reg2]
                future_values[reg2] = registers[reg1]

    def _handle_inc_dec_instruction(self, opcode, operands, registers, future_values, will_change):
        """Handle INC/DEC instructions."""
        if len(operands) == 1:
            dest = self._get_dest_register(operands[0])
            if dest and dest in registers:
                will_change.add(dest)
                try:
                    val = int(registers[dest], 16)
                    val = (val + 1) if opcode == 'inc' else (val - 1)
                    future_values[dest] = "%016x" % (val & ((1 << 64) - 1))
                except:
                    future_values[dest] = "???"

    def _handle_stack_instruction(self, opcode, operands, registers, future_values, will_change):
        """Handle PUSH/POP instructions."""
        will_change.add('rsp')
        rsp_val = None
        
        if 'rsp' in registers:
            try:
                current_rsp = int(registers['rsp'], 16)
                rsp_val = current_rsp - 8 if opcode == 'push' else current_rsp + 8
                future_values['rsp'] = "%016x" % rsp_val
            except:
                future_values['rsp'] = "???"
        
        if opcode == 'pop' and len(operands) == 1:
            dest = self._get_dest_register(operands[0])
            if dest:
                will_change.add(dest)
                future_values[dest] = "???"

    def _handle_math_instruction(self, future_values, will_change):
        """Handle math instructions (MUL, DIV, etc.)."""
        will_change.update(['rax', 'rdx'])
        future_values.update({'rax': "???", 'rdx': "???"})

    def _handle_control_flow_instruction(self, opcode, registers, future_values, will_change):
        """Handle control flow instructions."""
        will_change.add('rsp')
        if 'rsp' in registers:
            try:
                current_rsp = int(registers['rsp'], 16)
                # Adjust RSP based on instruction
                rsp_val = current_rsp - 8 if opcode == 'call' else current_rsp + 8
                future_values['rsp'] = "%016x" % rsp_val
            except:
                future_values['rsp'] = "???"

class WinDbgSyncScript(GhidraScript):
    """Main script for synchronizing WinDbg with Ghidra."""
    def __init__(self):
        self.last_offset = None
        self.last_content = None
        self.sync_file = None
        self.cmd_file = None
        self.modules_file = None
        self.gui = None
        self.kernel_base = None
        
    def write_command(self, command):
        """Display a command for the user to copy into WinDbg."""
        print("\nEnter this command in WinDbg:\n%s\n%s\n%s" % 
              ("-" * 40, command, "-" * 40))
    
    def get_current_address(self):
        """Get the current address in Ghidra."""
        try:
            return currentAddress.getOffset() if currentAddress else None
        except:
            return None
    
    def go_to_address(self, address):
        """Navigate to a specific address in Ghidra."""
        try:
            image_base = long(currentProgram.getImageBase().getOffset())
            prog_addr = long(address) + image_base
            goTo(toAddr(prog_addr))
        except Exception as e:
            print("Error navigating to address %s: %s" % (hex(address) if address else "None", str(e)))
    
    def parse_modules_file(self):
        """Parse the WinDbg modules file to find program's base address."""
        if not os.path.exists(self.modules_file):
            return None
        
        try:
            program_name = currentProgram.getName().lower().replace('.sys', '')
            
            with open(self.modules_file, 'r') as f:
                in_unloaded = False
                for line in f:
                    if 'Unloaded modules:' in line:
                        in_unloaded = True
                        continue
                    
                    if in_unloaded or not line.strip() or 'start' in line:
                        continue
                    
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        start_addr = parts[0].replace('`', '')
                        module_name = parts[2].lower()
                        
                        if program_name == module_name:
                            base_addr = int(start_addr, 16)
                            print("Found kernel module base: 0x%x for %s" % (base_addr, program_name))
                            return base_addr
                
                print("Warning: Could not find module base for program:", program_name)
                return None
                
        except Exception as e:
            print("Error parsing modules file:", str(e))
            return None
    
    def setup_files(self):
        """Setup synchronization files."""
        if not os.path.exists(TEMP_DIR):
            os.makedirs(TEMP_DIR)
        
        self.sync_file = os.path.join(TEMP_DIR, "state.txt")
        self.cmd_file = os.path.join(TEMP_DIR, "cmd.txt")
        self.modules_file = os.path.join(TEMP_DIR, "modules.txt")
        
        self.update_windbg_commands(init_mode=True)
        
        print("Synchronization files:")
        for file_type, path in [
            ("State file", self.sync_file),
            ("Command file", self.cmd_file),
            ("Modules file", self.modules_file)
        ]:
            print("%s: %s" % (file_type, path))

    def update_windbg_commands(self, init_mode=False):
        """
        Update the WinDbg command file with the latest commands.
        
        Args:
            init_mode (bool): If True, only write the module list command.
                            If False, write the normal state tracking commands.
        """
        if init_mode:
            # Initial command to get module list
            commands = [
                '.block {',
                '.logopen "%s"' % os.path.join(TEMP_DIR, "modules.txt"),
                'lm',
                '.logclose',
                '}'
            ]
        else:
            # Format kernel base as positive hex value
            kernel_base_str = "0x%x" % self.kernel_base
            
            # This is really ugly, but we're limited by WinDbg itself here...
            commands = [
                '.block {',
                # First get breakpoints
                '.logopen "%s"' % os.path.join(TEMP_DIR, "breakpoints.txt"),
                'bl',
                '.logclose',
                '.logopen "%s"' % os.path.join(TEMP_DIR, "state.txt"),
                '.printf "{\\"rip\\":\\"%016x\\",", (@rip - ' + kernel_base_str + ')',  # Adjusted RIP for Ghidra
                # Use full 64-bit values for registers
                '.printf "\\"registers\\":{\\"rax\\":\\"%p\\",", @rax',
                '.printf "\\"rbx\\":\\"%p\\",", @rbx',
                '.printf "\\"rcx\\":\\"%p\\",", @rcx',
                '.printf "\\"rdx\\":\\"%p\\",", @rdx',
                '.printf "\\"rsi\\":\\"%p\\",", @rsi',
                '.printf "\\"rdi\\":\\"%p\\",", @rdi',
                '.printf "\\"rsp\\":\\"%p\\",", @rsp',
                '.printf "\\"rbp\\":\\"%p\\",", @rbp',
                '.printf "\\"r8\\":\\"%p\\",", @r8',
                '.printf "\\"r9\\":\\"%p\\",", @r9',
                '.printf "\\"r10\\":\\"%p\\",", @r10',
                '.printf "\\"r11\\":\\"%p\\",", @r11',
                '.printf "\\"r12\\":\\"%p\\",", @r12',
                '.printf "\\"r13\\":\\"%p\\",", @r13',
                '.printf "\\"r14\\":\\"%p\\",", @r14',
                '.printf "\\"r15\\":\\"%p\\",", @r15',
                '.printf "\\"efl\\":\\"%p\\"}", @efl',
                '.printf ",\\"segments\\":{\\"cs\\":\\"%04x\\",", @cs',
                '.printf "\\"ds\\":\\"%04x\\",", @ds',
                '.printf "\\"es\\":\\"%04x\\",", @es',
                '.printf "\\"fs\\":\\"%04x\\",", @fs',
                '.printf "\\"gs\\":\\"%04x\\",", @gs',
                '.printf "\\"ss\\":\\"%04x\\"}", @ss',
                '.printf ",\\"memory\\":{\\"code\\":\\""',
                'r @$t0 = 0',
                '.for (r @$t0 = 0; @$t0 < 0x10; r @$t0 = @$t0 + 1) { .printf "%02x", by(@rip+@$t0) }',
                '.printf "\\"}"',
                '.printf "}\\n"',
                '.logclose',
                '.logopen "%s"' % os.path.join(TEMP_DIR, "stack.txt"),
                'kn',
                '.logclose',
                '}'
            ]
        
        with open(self.cmd_file, 'w') as f:
            f.write('\n'.join(commands))

    def parse_state_file(self):
        """Parse the WinDbg state file with improved error handling."""
        try:
            if not os.path.exists(self.sync_file):
                return None
            
            if not wait_for_file_unlock(self.sync_file):
                return None
            
            with open(self.sync_file, 'r') as f:
                content = f.read()
            
            for line in content.splitlines():
                if line.startswith('{"rip"') and line.endswith('}'):
                    if line != self.last_content:
                        self.last_content = line
                        return json.loads(line)
            
            return None
            
        except IOError as e:
            print("IO Error reading state file:", str(e))
            return None
        except Exception as e:
            print("Error parsing state file:", str(e))
            return None
        
    def parse_breakpoints_file(self):
        """Parse the WinDbg breakpoints file."""
        breakpoints = []
        breakpoints_file = os.path.join(TEMP_DIR, "breakpoints.txt")
        
        try:
            if not os.path.exists(breakpoints_file):
                return breakpoints
            
            with open(breakpoints_file, 'r') as f:
                lines = f.readlines()
            
            # Parse breakpoint lines
            for line in lines:
                line = line.strip()
                if not line or line.startswith('Opened log file') or line.startswith('Closing'):
                    continue
                
                # Example line format:
                # 0 e Disable Clear  fffff805`6091bef0     0001 (0001) nipalk!nipalDispatch
                try:
                    parts = line.split()
                    if len(parts) < 7:  # Need at least ID, status, flags, address, and rest
                        continue
                    
                    bp_id = parts[0]
                    status = parts[1]  # 'e' for enabled, 'd' for disabled
                    addr = None
                    description = ""
                    
                    # Find the address (format: fffff805`6091bef0)
                    for part in parts:
                        if '`' in part:
                            addr = part.replace('`', '')
                            break
                    
                    if not addr or addr == "00000000`00000000":
                        continue
                    
                    # Get everything after the (0001) part as description
                    desc_start = line.find('(0001)')
                    if desc_start != -1:
                        description = line[desc_start + 7:].strip()
                    
                    try:
                        kernel_addr = int(addr, 16)
                        prog_addr = kernel_addr - self.kernel_base
                        addr_str = "0x%x" % prog_addr
                    except ValueError:
                        addr_str = addr
                    
                    # Create formatted description with status
                    status_str = "Enabled" if status == 'e' else "Disabled"
                    formatted_desc = "[%s] %s" % (status_str, description)
                    
                    breakpoints.append({
                        'id': bp_id,
                        'address': addr_str,
                        'description': formatted_desc,
                        'status': status
                    })
                
                except Exception as e:
                    print("Error parsing breakpoint line: %s" % str(e))
                    print("Line was: %s" % line)
                    continue
            
            return breakpoints
            
        except Exception as e:
            print("Error parsing breakpoints file: %s" % str(e))
            import traceback
            traceback.print_exc()
            return []
    
    def run(self):
        """Main script execution loop."""
        try:
            # Initialize
            state = getState()
            console = state.getTool().getService(ghidra.app.services.ConsoleService)
            console.clearMessages()

            print_startup_message()
            
            print("Starting WinDbg synchronization script...")
            self.setup_files()
            
            # Wait for modules file
            start_time = time.time()
            while not os.path.exists(self.modules_file):
                if time.time() - start_time > 20:
                    print("Timeout waiting for modules file")
                    return
                time.sleep(0.1)
            
            # Get kernel base and update commands
            self.kernel_base = self.parse_modules_file()
            if not self.kernel_base:
                print("Could not determine kernel base")
                return
            
            self.update_windbg_commands(init_mode=False)
            
            # Create and show GUI
            print("\nScript started successfully")
            print("Kernel base: 0x%x" % self.kernel_base)
            print("Image base: 0x%x" % currentProgram.getImageBase().getOffset())
            print("\nWaiting for WinDbg updates...")
            
            self.gui = DebuggerGUI(self.kernel_base, self)
            self.gui.setVisible(True)
            
            # Main update loop
            while not monitor.isCancelled() and self.gui.isVisible():
                try:
                    state = self.parse_state_file()
                    if state:
                        self._handle_state_update(state)
                    Thread.sleep(100)
                except Exception as e:
                    print("Error in monitor loop:", str(e))
                    Thread.sleep(1000)
                    
        except Exception as e:
            print("Error during initialization:", str(e))
        finally:
            if self.gui:
                self.gui.dispose()
    
    def adjust_address(self, addr_str):
        """Convert kernel address to program space address."""
        try:
            # Parse hex string as int
            offset = int(addr_str, 16)
            # Add to image base
            program_addr = currentProgram.getImageBase().getOffset() + offset
            return program_addr
        except Exception as e:
            print("Error adjusting address:", str(e))
            return None
    
    def get_function_at(self, addr):
        """Get function name at the given address."""
        try:
            # addr is already a Ghidra Address object at this point
            function = getFunctionContaining(addr)
            
            if function is not None:
                return function.getName(True)  # True to get full, demangled name
                
            return "<no function>"
        except Exception as e:
            print("Error getting function name:", str(e))
            print("Address was:", addr)  # Debug print
            return "<error>"
    
    def _handle_state_update(self, state):
        """Handle state updates from WinDbg."""
        try:
            adjusted_addr = self.adjust_address(state['rip'])
            if adjusted_addr != self.last_offset:
                print("\nNavigating to offset: 0x%x" % adjusted_addr)
                addr = toAddr(adjusted_addr)
                goTo(addr)
                
                # Update GUI with current instruction and function
                cu = getCurrentProgram().getListing().getCodeUnitAt(addr)
                function_name = self.get_function_at(addr)
                instruction = cu.toString() if cu else "<RIP is outside of module>"
                
                self.gui.set_instruction(instruction, function_name, getCurrentProgram(), addr)
                self.last_offset = adjusted_addr
                self.gui.update_registers(state, instruction)
            else:
                self.gui.update_registers(state)
            
            # Update stack and breakpoints
            self.gui.update_stack(os.path.join(TEMP_DIR, "stack.txt"))
            self.gui.update_breakpoints(self.parse_breakpoints_file())
            
        except Exception as e:
            print("Error handling state update:", str(e))

if __name__ == '__main__':
    WinDbgSyncScript().run()
