package samlGabLib;

import java.util.ArrayList;
import java.util.List;

public class SamlHeaderCustomData {

	
	private List<DataPair> listaCampos = null;
	
	public SamlHeaderCustomData() {
		listaCampos = new ArrayList<DataPair>();
	}

	public List<DataPair> getList(){
		return this.listaCampos;
	}
	
	public void appendDataPair(String field, String value) throws SamlHeaderBuilderException{
		if(listaCampos != null){
			listaCampos.add(new DataPair(field,value));
		}else{
			throw new SamlHeaderBuilderException(new NullPointerException("Lista de campos no inicializada"));
		}
	}
		
}
