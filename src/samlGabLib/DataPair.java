package samlGabLib;

public class DataPair {

	private DataPair() {
		// TODO Auto-generated constructor stub
	}
	
	
	private String field ="";
	private String value ="";
	
	public DataPair(String field, String value){
		this.field = field;
		this.value = value;
	}
	
	public String getField(){
		return this.field;
	}
	
	public String getValue(){
		return this.value;
	}

}
