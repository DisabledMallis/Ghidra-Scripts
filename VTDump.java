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

public class VTDump extends GhidraScript {

    ArrayList<String> funcNames = new ArrayList<String>();
    public Address deref(Address addr) throws Exception {
	return addr.getNewAddress(getLong(addr));
    }

    public void run() throws Exception {
	println("Hello");
	Address firstInTable = currentAddress;
	println("Beginning of VTable: "+firstInTable);
	println("Test: "+deref(firstInTable));
	Address nextInTable = firstInTable;
	int maxIter = 500;

	int currentIter = 0;

	String output = "\n";
//Get all func names and gen vtable code
	while(getFunctionAt(deref(nextInTable)) != null){

		Function function = getFunctionAt(deref(nextInTable));
		if (function == null) {
			println("Func is null");
			break;
		}

		println("Current: "+nextInTable + " Func name: "+function.getName());
/*
 * Return types
 */
		String returnType = function.getReturnType().getName().replace(" *","*");
//Sanitize return type
//Make string return types not ugly
		if(returnType.contains("basic_string")){
			returnType = "std::string*";
		}
//if the return type contains a capital, it cannot be primitive and must be a class by mojang's standards (or so it seems)
		if(returnType.matches(".*[A-Z].*")){
//all classes are returned as pointers, so this must be one, right?
			if(!returnType.contains("*")){
				returnType+="*";
			}
//Add class definition because it may not be defined already
			returnType = "class "+returnType;
		}
/*
 * Func name
 */
//Sanitize function name
		String funcName = function.getName();
//if funcname contains a @ its mangled, prob dont need it anyway so lets just give a generic ass name. Same goes for < and > cuz templates long and ugly
		if(funcName.contains("@") || funcName.contains("<") || funcName.contains(">")){
			funcName = "UndefinedFunc_"+currentIter;
		}
/*
 * Parameters
 */
		String paramsStr = "";
		Parameter[] params = function.getParameters();
		int count = 0;
		for(Parameter param : params){
			String type = param.getFormalDataType().getName();
			if(funcName.contains("UndefinedFunc_")){
				type="void*";
			}
			String name = param.getName();
			if(count==0){ count++; continue; }
			if(type.matches(".*[A-Z].*")){
				if(!type.contains("*")){
					type+="*";
				}
				type = "class "+type;
			}
			type = type.replace(" *", "*");
			paramsStr += "{TYPE} {NAME}".replace("{TYPE}", type).replace("{NAME}", name);
			if(params.length != count+1){
				paramsStr += ", ";
			}
			//println("Count: "+count+" size: "+params.length);
			count++;
		}
		output += "virtual "+returnType+" "+funcName+"("+paramsStr+") {}\n";

		nextInTable = nextInTable.add(8);
		maxIter--;
		if(maxIter<0){
			println("FAILED");
			break;
		}
		/*boolean yesOrNo = askYesNo("yes or no", "is this a yes/no question?");
		println("Yes or No? " + yesOrNo);

		if(!yesOrNo){ break; }*/
		currentIter++;
		continue;
	}
	println(output);
    }
}
