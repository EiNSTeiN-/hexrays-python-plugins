import idautils
import idaapi
import idc

import hexrays
import traceback

try:
    from PyQt4 import QtCore, QtGui
    print 'Using PyQt'
except:
    print 'PyQt not available'
    
    try:
        from PySide import QtGui, QtCore
        print 'Using PySide'
    except:
        print 'PySide not available'

class XrefsForm(idaapi.PluginForm):
    
    def __init__(self, target):
        
        idaapi.PluginForm.__init__(self)
        
        self.target = target
        
        if type(self.target) == hexrays.cfunc_t:
            
            self.__ea = self.target.entry_ea
            self.__name = 'Xrefs of %x' % (self.__ea, )
            
        elif type(self.target) == hexrays.cexpr_t and self.target.opname == 'obj':
            
            self.__ea = self.target.obj_ea
            self.__name = 'Xrefs of %x' % (self.__ea, )
            
        else:
            raise ValueError('cannot show xrefs for this kind of target')
        
        return
    
    def OnCreate(self, form):
        
        # Get parent widget
        try:
            self.parent = self.FormToPySideWidget(form)
        except:
            self.parent = self.FormToPyQtWidget(form)
        
        self.populate_form()
        
        return
    
    def Show(self):
        idaapi.PluginForm.Show(self, 'bla')
        return
    
    def populate_form(self):
        # Create layout
        layout = QtGui.QVBoxLayout()

        layout.addWidget(QtGui.QLabel(self.__name))
        self.table = QtGui.QTableWidget()
        layout.addWidget(self.table)
        
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderItem(0, QtGui.QTableWidgetItem("Address"))
        self.table.setHorizontalHeaderItem(1, QtGui.QTableWidgetItem("Function"))
        self.table.setHorizontalHeaderItem(2, QtGui.QTableWidgetItem("Line"))
        
        self.table.setColumnWidth(0, 80)
        self.table.setColumnWidth(1, 150)
        self.table.setColumnWidth(2, 450)
        
        #~ self.table.setSelectionMode(QtGui.QAbstractItemView.NoSelection)
        self.table.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows )
        self.parent.setLayout(layout)
        
        self.populate_table()
        
        return
    
    def get_decompiled_line(self, cfunc, ea):
        
        if ea not in cfunc.eamap:
            print 'strange, %x is not in %x eamap' % (ea, cfunc.entry_ea)
            return
        
        insnvec = cfunc.eamap[ea]
        
        lines = []
        for stmt in insnvec:
            d = stmt.details
            
            s = stmt.details.print1(cfunc.__deref__())
            s = idaapi.tag_remove(s)
            lines.append(s)
        
        return '\n'.join(lines)
    
    def populate_table(self):
        
        frm = [x.frm for x in idautils.XrefsTo(self.__ea)]
        
        items = []
        for ea in frm:
            try:
                #~ print 'decompiling', hex(ea)
                cfunc = hexrays.decompile(ea)
                cfunc.refcnt += 1
                #~ print repr(cfunc)
                
                items.append((ea, idc.GetFunctionName(cfunc.entry_ea), self.get_decompiled_line(cfunc, ea)))
                
            except Exception as e:
                print 'could not decompile: %s' % (str(e), )

        self.table.setRowCount(len(items))
        
        i = 0
        for item in items:
            address, func, line = item
            item = QtGui.QTableWidgetItem('0x%x' % (address, ))
            item.setFlags(item.flags() ^ QtCore.Qt.ItemIsEditable)
            self.table.setItem(i, 0, item)
            item = QtGui.QTableWidgetItem(func)
            item.setFlags(item.flags() ^ QtCore.Qt.ItemIsEditable)
            self.table.setItem(i, 1, item)
            item = QtGui.QTableWidgetItem(line)
            item.setFlags(item.flags() ^ QtCore.Qt.ItemIsEditable)
            self.table.setItem(i, 2, item)
            
            i += 1
        
        self.table.resizeRowsToContents()
        
        return
    
    def OnClose(self, form):
        pass

class hexrays_callback_info(object):
    
    def __init__(self):
        self.vu = None
        return
    
    def menu_callback(self):
        #~ print 'xrefs menu clicked'
        self.show_xrefs(self.vu)
        return 0
    
    def show_xrefs(self, vu):
        #~ print 'showing xrefs'
        
        vu.get_current_item(hexrays.USE_KEYBOARD)
        item = vu.item
        #~ print 'current item is', repr(item)
        
        if item.citype == hexrays.VDI_EXPR:
            # an expression is selected. verify that it's either a cot_obj, cot_memref or cot_memptr
            sel = item.it.to_specific_type
            #~ print 'ctree item xrefs'
            if sel.opname == 'obj':
                print 'xref of', repr(sel.obj_ea)
            else:
                print 'cannot xref this item, please xref global functions or variables.'
                sel = None
        elif item.citype == hexrays.VDI_LVAR:
            # local variables are not xref-able
            #~ print 'lvar item'
            #~ sel = item.l
            pass
            sel = None
        elif item.citype == hexrays.VDI_FUNC:
            # if the function itself is selected, show xrefs to it.
            print 'function xrefs'
            sel = item.f
        else:
            sel = None
        
        if sel:
            print 'selection', repr(sel)
            form = XrefsForm(sel)
            form.Show()
        
        return
    
    def event_callback(self, event, *args):
        
        try:
            if event == hexrays.hxe_keyboard:
                print 'keyboard'
                vu, keycode, shift = args
                
                if idaapi.lookup_key_code(keycode, shift, True) == idaapi.get_key_code("X") and shift == 0:
                    self.show_xrefs(vu)
                    
                    return 1
                
            elif event == hexrays.hxe_right_click:
                print 'right click'
                self.vu = args[0]
                hexrays.add_custom_viewer_popup_item(self.vu.ct, "Xrefs", "X", self.menu_callback)
            
        except:
            traceback.print_exc()
            
        
        return 0

i = hexrays_callback_info()
hexrays.install_callback(i.event_callback)


