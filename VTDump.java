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

	String output = "";
//Get all func names and gen vtable code
	while(getFunctionAt(deref(nextInTable)) != null){

		Function function = getFunctionAt(deref(nextInTable));
		if (function == null) {
			println("Func is null");
			break;
		}

		println("Current: "+nextInTable + " Func name: "+function.getName());
		output += "virtual void "+function.getName()+"() {}\n";

		nextInTable = nextInTable.add(8);
		maxIter--;
		if(maxIter<0){
			println("FAILED");
			break;
		}
		/*boolean yesOrNo = askYesNo("yes or no", "is this a yes/no question?");
		println("Yes or No? " + yesOrNo);

		if(!yesOrNo){ break; }*/
		continue;
	}
	println(output);
    }
}
