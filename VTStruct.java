//Generates a structure for the vtable
//@author DisabledMallis
//@category Symbol
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.*;
import ghidra.app.util.html.diff.DataTypeDiffBuilder;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

import java.util.*;
import java.util.regex.Pattern;

import org.relaxng.datatype.DatatypeBuilder;

public class VTStruct extends GhidraScript {

	final List<String> funcNames = new ArrayList<String>();

	public static final Pattern MOJANG_CLASS_STANDARD = Pattern.compile(".*[A-Z].*");
	public static final String BASIC_STRING_TYPE = "basic_string";
	public static final String UNDEFINED_FUNCTION = "UndefinedFunc_";
	public static final String POINTER_TYPE = "*";
	public static final String VOID_POINTER_TYPE = "void" + POINTER_TYPE;
	public static final String STD_STRING_POINTER_TYPE = "std::string" + POINTER_TYPE;
	public static final String TYPE_PLACEHOLDER = "{TYPE}";
	public static final String NAME_PLACEHOLDER = "{NAME}";
	public static final String TYPE_NAME_PLACEHOLDER = TYPE_PLACEHOLDER + " " + NAME_PLACEHOLDER;
	public static final boolean DEBUG = true;

	public String undefinedNearestPrimitive(String undefinedType) {
		if(undefinedType.contains("undefined")) {
			if(undefinedType.equals("undefined")) {
				return "void*";
			}
			else {
				int size = Integer.parseInt(undefinedType.substring(9));
				switch(size) {
				case 1:
					return "uint8_t";
				case 2:
					return "uint16_t";
				case 4:
					return "uint32_t";
				case 8:
					return "uint64_t";
				}
			}
		}
		return undefinedType;
	}

	public Address deref(Address addr) throws Exception {
		switch(addr.getPointerSize()) {
		case 4:
			return addr.getNewAddress(getInt(addr));
		case 8:
		default:
			return addr.getNewAddress(getLong(addr));
		}
	}

	public void run() throws Exception {
		Address firstInTable = currentAddress;

        String vtableName = "vtable";
        String className = "anonymous";

        Symbol symbol = this.getSymbolAt(firstInTable);
        if(symbol != null)
        {
            vtableName = symbol.getName();
            Symbol parent = symbol.getParentSymbol();
            if(parent != null)
            {
                className = parent.getName();
            }
        }

        String vtableDataType = className + "_" + vtableName;
        println("Found vtable " + vtableName + " for " + className);

        CategoryPath vtableCategoryPath = new CategoryPath("/vtable_structures");

        var datatypeManager = this.getCurrentProgram().getDataTypeManager();
        var vtableCategory = datatypeManager.getCategory(vtableCategoryPath);
        if(vtableCategory == null)
        {
            vtableCategory = datatypeManager.createCategory(vtableCategoryPath);
        }

        Address nextInTable = firstInTable;

        int maxIter = 500;
		int currentIter = 0;
		// Calc the size of the vtable
		while (getFunctionAt(deref(nextInTable)) != null) {
			Function function = getFunctionAt(deref(nextInTable));
			if (function == null) {
				println("Func is null (reached end #1)");
				break;
			}
            Symbol refSymbol = this.getSymbolAt(nextInTable);
            if(refSymbol != null)
            {
                vtableName = refSymbol.getName();
                Symbol parent = refSymbol.getParentSymbol();
                if(parent != null)
                {
                    if(!className.equals(parent.getName()))
                    {
                        println("Found another vtable!");
                        break;
                    }
                }
            }
            nextInTable = nextInTable.add(nextInTable.getPointerSize());
			if (currentIter > maxIter) {
				println("FAILED #1");
				break;
			}
			currentIter++;
			continue;
		}
        int vtableSize = currentIter;

        DataTypePath vtableTypePath = new DataTypePath(vtableCategoryPath, vtableDataType);
        StructureDataType dataType = (StructureDataType)datatypeManager.getDataType(vtableTypePath);
        DataType voidPtr = datatypeManager.getPointer(null, firstInTable.getPointerSize());
        if(dataType == null)
        {
            dataType = new StructureDataType(vtableDataType, 0);
        }

        nextInTable = firstInTable;
		currentIter = 0;
		// Get all func names and generate the structure info
		while (getFunctionAt(deref(nextInTable)) != null) {
            if (currentIter > vtableSize) {
				println("Reached end!");
				break;
			}

			Function function = getFunctionAt(deref(nextInTable));
			if (function == null) {
				println("Func is null (reached end #2)");
				break;
			}

			/*
			 * Func name
			 */
			// Sanitize function name
			String funcName = function.getName();
            // Check if the function itself has symbol info
            Symbol[] funcSymbols = this.getCurrentProgram().getSymbolTable().getSymbols(function.getEntryPoint());
            if(funcSymbols.length != 0)
            {
                //If so, find a matching symbol for the class
                for (Symbol s : funcSymbols) {
                    //First check if its mangled and can be demangled
                    DemangledObject demangled = DemanglerUtil.demangle(s.getName());
                    //Check if it was successfully demangled, and if so if its a function
                    if(demangled != null && demangled instanceof DemangledFunction)
                    {
                        //If its a function, check if it matches
                        DemangledFunction demangledFunc = (DemangledFunction)demangled;
                        Demangled demangledNamespace = demangledFunc.getNamespace();
                        if(demangledNamespace == null)
                            continue;
                        
                        if(demangledNamespace.getName().equals(className))
                        {
                            //If so set the name an move on
                            funcName = demangledFunc.getName();
                            break;
                        }
                    }

                    //Otherwise try checking the parent symbol
                    Symbol parent = s.getParentSymbol();
                    if(parent != null)
                    {
                        //If the parent if the class we want
                        if(parent.getName().contains(className))
                        {
                            //Match found
                            funcName = s.getName();
                            break;
                        }
                    }
                }
            }

            //Add the func to the dataType
            dataType.insertAtOffset(currentIter*nextInTable.getPointerSize(), voidPtr, nextInTable.getPointerSize(), funcName, funcName);
			
            nextInTable = nextInTable.add(nextInTable.getPointerSize());
			currentIter++;
			continue;
		}

        //Add the final datatype
        vtableCategory.addDataType(dataType, null);
        println("Added DataType " + dataType.getDisplayName());

        //Put the vtable in the listing
        Listing listing = this.getCurrentProgram().getListing();
        listing.clearCodeUnits(firstInTable, firstInTable.add(vtableSize*firstInTable.getPointerSize()), true);
        //listing.createData(firstInTable, new ArrayDataType(voidPtr, vtableSize, firstInTable.getPointerSize()));
        listing.createData(firstInTable, dataType, vtableSize*firstInTable.getPointerSize());

        return;
    }
}