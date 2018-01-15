package com.highershine.pki.servlet;
public class Util {
	/***
	 * 身份证号15位转18�?
	 * @param id
	 * @return
	 */
	public static final String getIDCard15To18(String id) {
		
	    // 若是15位，则转换成18位；否则直接返回ID
	    if (15 == id.length()) {
	        final int[] W = { 7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4,
	                2, 1 };
	        final String[] A = { "1", "0", "X", "9", "8", "7", "6", "5", "4",
	                "3", "2" };
	        int i=0, j=0, s = 0;
	        String newid;
	        newid = id;
	        newid = newid.substring(0, 6) + "19" + newid.substring(6, id.length());
	        for (i = 0; i < newid.length(); i++) {
	            s = s + j;
	        }
	        s = s % 11;
	        newid = newid + A[s];
	        return newid;
	    } else {
	    	return id;
	    }

	}
	
}
