//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
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
import java.util.List;

public class VTDump_x86 extends GhidraScript {

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

	public Address deref(Address addr) throws Exception {
		return addr.getNewAddress(getInt(addr));
	}

	public void run() throws Exception {
		println("Hello");
		Address firstInTable = currentAddress;
		println("Beginning of VTable: " + firstInTable);
		println("Test: " + deref(firstInTable));
		Address nextInTable = firstInTable;
		int maxIter = 500;

		int currentIter = 0;

		String output = "\n";
		// Get all func names and gen vtable code
		while (getFunctionAt(deref(nextInTable)) != null) {

			Function function = getFunctionAt(deref(nextInTable));
			if (function == null) {
				println("Func is null");
				break;
			}

			println("Current: " + nextInTable + " Func name: " + function.getName());
			/*
			 * Return types
			 */
			String returnType = function.getReturnType().getName().replace(" " + POINTER_TYPE, POINTER_TYPE);
			// Sanitize return type
			// Make string return types not ugly
			if (returnType.contains(BASIC_STRING_TYPE)) {
				returnType = STD_STRING_POINTER_TYPE;
			}
			// if the return type contains a capital, it cannot be primitive and must be a
			// class by mojang's standards (or so it seems)
			if (MOJANG_CLASS_STANDARD.matcher(returnType).matches()) {
				// all classes are returned as pointers, so this must be one, right?
				if (!returnType.contains(POINTER_TYPE)) {
					returnType += POINTER_TYPE;
				}
				// Add class definition because it may not be defined already
				returnType = "class " + returnType;
			}
			/*
			 * Func name
			 */
			// Sanitize function name
			String funcName = function.getName();
			// if funcname contains a @ its mangled, prob dont need it anyway so lets just
			// give a generic ass name. Same goes for < and > cuz templates long and ugly
			String[] badFuncNames = { "@", "<", ">", "`", "'" };
			for (String chr : badFuncNames) {
				if (funcName.contains(chr)) {
					funcName = UNDEFINED_FUNCTION + currentIter;
				}
			}
			/*
			 * Parameters
			 */
			String paramsStr = "";
			Parameter[] params = function.getParameters();
			int count = 0;
			for (Parameter param : params) {
				String type = param.getFormalDataType().getName();
				if (funcName.contains(UNDEFINED_FUNCTION)) {
					type = VOID_POINTER_TYPE;
				}
				String name = param.getName();
				if (count == 0) {
					count++;
					continue;
				}
				if (MOJANG_CLASS_STANDARD.matcher(type).matches()) {
					if (!type.contains(POINTER_TYPE)) {
						type += POINTER_TYPE;
					}
					type = "class " + type;
				}
				type = type.replace(" " + POINTER_TYPE, POINTER_TYPE);
				paramsStr += TYPE_NAME_PLACEHOLDER.replace(TYPE_PLACEHOLDER, type).replace(NAME_PLACEHOLDER, name);
				if (params.length != count + 1) {
					paramsStr += ", ";
				}
				// println("Count: "+count+" size: "+params.length);
				count++;
			}
			output += "virtual " + returnType + " " + funcName + "(" + paramsStr + ") {}\n";

			nextInTable = nextInTable.add(8);
			maxIter--;
			if (maxIter < 0) {
				println("FAILED");
				break;
			}
			/*
			 * boolean yesOrNo = askYesNo("yes or no", "is this a yes/no question?");
			 * println("Yes or No? " + yesOrNo);
			 * 
			 * if(!yesOrNo){ break; }
			 */
			currentIter++;
			continue;
		}
		println(output);
	}
}
