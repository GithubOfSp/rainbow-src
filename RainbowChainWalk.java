import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;

public class RainbowChainWalk {
	static final String alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	static final String alpha_space = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";
	static final String alpha_numeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	static final String alpha_numeric_space = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
	static final String alpha_numeric_symbol14= "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=";
	static final String alpha_numeric_symbol14_space= "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+= ";
	static final String all = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=~`[]{}|\\:;\"\'<>,.?/";
	static final String all_space = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=~`[]{}|\\:;\"\'<>,.?/ ";
	static final String alpha_numeric_symbol32_space = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=~`[]{}|\\:;\"\'<>,.?/ ";
	static final String numeric = "0123456789";
	static final String numeric_space = "0123456789 ";
	static final String loweralpha= "abcdefghijklmnopqrstuvwxyz";
	static final String loweralpha_space= "abcdefghijklmnopqrstuvwxyz ";
	static final String loweralpha_numeric= "abcdefghijklmnopqrstuvwxyz0123456789";
	static final String loweralpha_numeric_space= "abcdefghijklmnopqrstuvwxyz0123456789 ";
	static final String loweralpha_numeric_symbol14 = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_+=";
	static final String loweralpha_numeric_all 	= "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_+=~`[]{}|\\:;\"\'<>,.?/";
	static final String loweralpha_numeric_symbol32_space= "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_+=~`[]{}|\\:;\"\'<>,.?/ ";
	static final String mixalpha= "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	static final String mixalpha_space= "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ";
	static final String mixalpha_numeric= "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	static final String mixalpha_numeric_space= "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
	static final String mixalpha_numeric_symbol14 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=";
	static final String mixalpha_numeric_all= "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=~`[]{}|\\:;\"\'<>,.?/";
	static final String mixalpha_numeric_symbol32_space= "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=~`[]{}|\\:;\"\'<>,.?/ ";
	static final String mixalpha_numeric_all_space= "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=~`[]{}|\\:;\"\'<>,.?/ ";
	static final String symbol= "!@#$%^&*()-_+=~`[]{}|\\:;\"\'<>,.?/";

	static class NoSuchCharsetException extends Exception
	{
		/**
		 * 
		 */
		private static final long serialVersionUID = 1348334817840742944L;

		public NoSuchCharsetException(String msg)
		{
			super(msg);
		}
	}
	
	static byte[] getCharsetBytes(String charset) throws Exception
	{
		if(charset.equalsIgnoreCase("alpha")) return alpha.getBytes();
	    else if(charset.equalsIgnoreCase("alpha-space")) return alpha_space.getBytes();
	    else if(charset.equalsIgnoreCase("alpha-numeric")) return alpha_numeric.getBytes();
	    else if(charset.equalsIgnoreCase("alpha-numeric-space")) return alpha_numeric_space.getBytes();
	    else if(charset.equalsIgnoreCase("alpha-numeric-symbol14")) return alpha_numeric_symbol14.getBytes();
	    else if(charset.equalsIgnoreCase("alpha-numeric-symbol14-space")) return alpha_numeric_symbol14_space.getBytes();
	    else if(charset.equalsIgnoreCase("all")) return all.getBytes();
	    else if(charset.equalsIgnoreCase("all-space")) return all_space.getBytes();
	    else if(charset.equalsIgnoreCase("alpha-numeric-symbol32-space")) return alpha_numeric_symbol32_space.getBytes();
//	    else if(charset.equalsIgnoreCase("lm-frt-cp437")) return lm_frt_cp437.getBytes();
//	    else if(charset.equalsIgnoreCase("lm-frt-cp850")) return lm_frt_cp850.getBytes();
//	    else if(charset.equalsIgnoreCase("lm-frt-cp437-850")) return lm_frt_cp437_850.getBytes();
	    else if(charset.equalsIgnoreCase("numeric")) return numeric.getBytes();
	    else if(charset.equalsIgnoreCase("numeric-space")) return numeric_space.getBytes();
	    else if(charset.equalsIgnoreCase("loweralpha")) return loweralpha.getBytes();
	    else if(charset.equalsIgnoreCase("loweralpha-space")) return loweralpha_space.getBytes();
	    else if(charset.equalsIgnoreCase("loweralpha-numeric")) return loweralpha_numeric.getBytes();
	    else if(charset.equalsIgnoreCase("loweralpha-numeric-space")) return loweralpha_numeric_space.getBytes();
	    else if(charset.equalsIgnoreCase("loweralpha-numeric-symbol14")) return loweralpha_numeric_symbol14.getBytes();
	    else if(charset.equalsIgnoreCase("loweralpha-numeric-all")) return loweralpha_numeric_all.getBytes();
	    else if(charset.equalsIgnoreCase("loweralpha-numeric-symbol32-space")) return loweralpha_numeric_symbol32_space.getBytes();
	    else if(charset.equalsIgnoreCase("mixalpha")) return mixalpha.getBytes();
	    else if(charset.equalsIgnoreCase("mixalpha-space")) return mixalpha_space.getBytes();
	    else if(charset.equalsIgnoreCase("mixalpha-numeric")) return mixalpha_numeric.getBytes();
	    else if(charset.equalsIgnoreCase("mixalpha-numeric-space")) return mixalpha_numeric_space.getBytes();
	    else if(charset.equalsIgnoreCase("mixalpha-numeric-symbol14")) return mixalpha_numeric_symbol14.getBytes();
	    else if(charset.equalsIgnoreCase("mixalpha-numeric-all")) return mixalpha_numeric_all.getBytes();
	    else if(charset.equalsIgnoreCase("mixalpha-numeric-symbol32-space")) return mixalpha_numeric_symbol32_space.getBytes();
	    else if(charset.equalsIgnoreCase("mixalpha-numeric-all-space")) return mixalpha_numeric_all_space.getBytes();
	    else if(charset.equalsIgnoreCase("symbol")) return symbol.getBytes();
	    else throw new NoSuchCharsetException(charset);
	}
	     
	boolean FixedPlainLen = true;
	boolean MixedCharset = false;
	boolean PermutedCharset = false;
	byte[][] charset = null;
	byte[][] charsetFixed = null;
	int[] plainLenMin = null;
	int[] plainLenMax = null;	
	long plainSpaceTotal = 0;
	long[] partPlainSpaceTotal = null;
	BigInteger[] bigPartPlainSpaceTotal = null;
	long[][] plainSpaceUpToX = null;
	BigInteger[][] bigPlainSpaceUpToX = null;
	
	String alg;
	MessageDigest digest;	
	int tableIndex;	
	
	long index;
	byte[] plain;
	byte[] hash;
	
	RainbowChainWalk(String alg, String charset, int tableIndex) throws Exception
	{
		this.alg = alg;
		if(!alg.equalsIgnoreCase("ntlm")) 
		{
			digest = MessageDigest.getInstance(alg);
		}
		setCharset(charset);
		this.tableIndex = tableIndex;
		if(MixedCharset)
			calcPlainSpaceTotal_Mixed();
		else calcPlainSpaceTotal();
	}
	
	void setCharset(String charset) throws Exception
	{
		if(charset.startsWith("["))
		{
			if(!charset.endsWith("]")) throw new Exception("charset format error, \""+charset+"\".");
			MixedCharset = true;
			FixedPlainLen = false;
			charset = charset.substring(1, charset.length()-1);
		}
		if(charset.startsWith("("))
		{
			if(!charset.endsWith(")")) throw new Exception("charset format error, \""+charset+"\".");
			PermutedCharset = true;
			FixedPlainLen = false;
			charset = charset.substring(1, charset.length()-1);
		}
		String[] charsetParse = charset.split("#");
		int parts = charsetParse.length/2;
		this.charset = new byte[parts][];
		plainLenMin = new int[parts];
		plainLenMax = new int[parts];
		plainSpaceUpToX = new long[parts][];
		bigPlainSpaceUpToX = new BigInteger[parts][];
		partPlainSpaceTotal = new long[parts];
		bigPartPlainSpaceTotal = new BigInteger[parts];
		for(int i=0; i<charsetParse.length/2; i++)
		{
			this.charset[i] = getCharsetBytes(charsetParse[2*i]);
			String[] plainLenParse = charsetParse[2*i+1].split("-");
			if(plainLenParse.length==2)
			{
				FixedPlainLen = false;
			}
			plainLenMin[i] = Integer.valueOf(plainLenParse[0]);
			if(plainLenMin[i]<0 || PermutedCharset && plainLenMin[i]==0) throw new Exception("charset min length illegal, \""+charset+"\".");
			plainLenMax[i] = plainLenParse.length==2?Integer.valueOf(plainLenParse[1]):plainLenMin[i];
			plainSpaceUpToX[i] = new long[plainLenMax[i]-plainLenMin[i]+1];
			bigPlainSpaceUpToX[i] = new BigInteger[plainLenMax[i]-plainLenMin[i]+1];
			for(int j=0; j<bigPlainSpaceUpToX[i].length; j++)
			{
				bigPlainSpaceUpToX[i][j] = new BigInteger("0");
			}
		}
		if(FixedPlainLen==true)
		{
			ArrayList<String> mixCharset = new ArrayList<String>();
			for(int i=0; i<charsetParse.length/2; i++)
			{
				for(int j=0; j<Integer.valueOf(charsetParse[2*i+1]); j++)
				{
					mixCharset.add(charsetParse[2*i]);
				}
			}
			charsetFixed = new byte[mixCharset.size()][];
			for(int i=0; i<charsetFixed.length; i++)
			{
				charsetFixed[i] = getCharsetBytes(mixCharset.get(i));
			}
		}
	}
	
	static class PlainSpaceExceededException extends Exception
	{
		private static final long serialVersionUID = -4999915602818968755L;
		PlainSpaceExceededException(String msg)
		{
			super(msg);
		}
	}
	
	void calcPlainSpaceTotal() throws PlainSpaceExceededException {
		plainSpaceTotal = 1;
		BigInteger bigPlainSpaceTotal = new BigInteger("1");
		if(FixedPlainLen==true)
		{
			for(int i=0; i<charsetFixed.length; i++)
			{
				plainSpaceTotal *= charsetFixed[i].length;
				bigPlainSpaceTotal.multiply(new BigInteger(String.valueOf(charsetFixed[i].length)));
			}
		}
		else
		{
			for(int i=0; i<this.charset.length; i++)
			{
				long spaceSize = (long)Math.pow(this.charset[i].length, plainLenMin[i]);
				BigInteger bigSpaceSize = new BigInteger(String.valueOf(this.charset[i].length)).pow(plainLenMin[i]); 
				for(int j=plainLenMin[i]; j<plainLenMax[i]; j++)
				{
					plainSpaceUpToX[i][j-plainLenMin[i]+1] = plainSpaceUpToX[i][j-plainLenMin[i]]+spaceSize;
					bigPlainSpaceUpToX[i][j-plainLenMin[i]+1] = bigPlainSpaceUpToX[i][j-plainLenMin[i]].add(bigSpaceSize);
					spaceSize *= this.charset[i].length;
					bigSpaceSize = bigSpaceSize.multiply(new BigInteger(String.valueOf(this.charset[i].length)));
				}
				partPlainSpaceTotal[i] = plainSpaceUpToX[i][plainLenMax[i]-plainLenMin[i]]+spaceSize;
				bigPartPlainSpaceTotal[i] = bigPlainSpaceUpToX[i][plainLenMax[i]-plainLenMin[i]].add(bigSpaceSize);
			}
			for(long i:partPlainSpaceTotal)
			{
				plainSpaceTotal *= i;
			}
			for(BigInteger i:bigPartPlainSpaceTotal)
			{
				bigPlainSpaceTotal = bigPlainSpaceTotal.multiply(i);
			}
			if(PermutedCharset)
			{
				for(int i=1; i<=charset.length; i++)
				{
					plainSpaceTotal *= i;
					bigPlainSpaceTotal = bigPlainSpaceTotal.multiply(new BigInteger(String.valueOf(i)));
				}
			}
		}
		if(bigPlainSpaceTotal.compareTo(new BigInteger(String.valueOf(Long.MAX_VALUE)))>0)
		{
			throw new PlainSpaceExceededException("plainSpaceTotal: "+bigPlainSpaceTotal.toString());
		}
	}
	
	byte[][] mixedCharsetTable; //for the lookup of the length of each plain part corresponding to a certain index
	void calcPlainSpaceTotal_Mixed() throws PlainSpaceExceededException
	{
		//initial table
		int tableSize = 1;
		for(int i=0; i<charset.length; i++) tableSize *= plainLenMax[i]-plainLenMin[i]+1;
		mixedCharsetTable = new byte[tableSize+1][];
		mixedCharsetTable[0] = new byte[charset.length+8];
		int tableIndex = 1;
		
		//initial combination
		int[] plainLength = new int[charset.length];
		long[] spaceSize = new long[charset.length];
		for(int i=0; i<plainLength.length; i++)
		{
			plainLength[i] = plainLenMin[i];
			spaceSize[i] = (long)Math.pow(charset[i].length, plainLength[i]);
		}
		plainSpaceTotal = 0;
		BigInteger bigPlainSpaceTotal = new BigInteger("0");
		
		//combination of different plain length
		boolean hasNext = true;
		while(hasNext)//loop tableSize times
		{
			//calculate plain space size of current combination
			long totalSize = 1;
			BigInteger bigTotalSize = new BigInteger("1");
			for(long l:spaceSize)
			{
				totalSize *= l;
				bigTotalSize = bigTotalSize.multiply(new BigInteger(String.valueOf(l)));
			}
			int n = plainLength[0];
			for(int i=1; i<plainLength.length; i++)
			{
				int m = plainLength[i];
				n += m;
				int com = RainbowCalcTools.combination(m, n);
				totalSize *= com;
				bigTotalSize = bigTotalSize.multiply(new BigInteger(String.valueOf(com)));
			}
			plainSpaceTotal += totalSize;
			bigPlainSpaceTotal = bigPlainSpaceTotal.add(bigTotalSize);
			if(bigPlainSpaceTotal.compareTo(new BigInteger(String.valueOf(Long.MAX_VALUE)))>0)
			{
				throw new PlainSpaceExceededException("spaceSize:"+Arrays.toString(spaceSize)+" plainLength:"+Arrays.toString(plainLength)+" totalSize:"+bigTotalSize);
			}

			//fill in a row of table: total plain space + each plain length of current combination
			mixedCharsetTable[tableIndex] = new byte[8+plainLength.length];
			System.arraycopy(ByteBuffer.allocate(8).putLong(plainSpaceTotal).array(), 0, mixedCharsetTable[tableIndex], 0, 8);
			for(int i=0; i<plainLength.length; i++) mixedCharsetTable[tableIndex][i+8] = (byte)plainLength[i];
			tableIndex++;
			
			//renew combination
			for(int i=0; i<plainLength.length; i++)
			{
				if(plainLength[i]==plainLenMax[i])
				{
					if(i==plainLength.length-1) hasNext = false;
					plainLength[i] = plainLenMin[i];
					spaceSize[i] = (long)Math.pow(charset[i].length, plainLenMin[i]);
				}
				else
				{
					plainLength[i]++;
					spaceSize[i] *= charset[i].length;
					break;
				}
			}
		}
	}

	byte[] primaryIndexToPlain(int part, long index) {
		int plainLen = 0;
		for (plainLen = plainLenMax[part]; plainLen > plainLenMin[part]; plainLen--)
		{
			if (index >= plainSpaceUpToX[part][plainLen-plainLenMin[part]])
			{
				break;
			}
		}
		index -= plainSpaceUpToX[part][plainLen-plainLenMin[part]]; 
		byte[] plain = new byte[plainLen];
		for (int a = plainLen - 1; a >= 0; a--) {
			plain[a] = charset[part][(int)(index % charset[part].length)];
			index /= charset[part].length;
		}
		return plain;
	}
	
	void indexToPlain()
	{
		if(MixedCharset) indexToPlain_Mixed();
		else if(FixedPlainLen==true)
		{
			plain = new byte[charsetFixed.length];
			for(int i=plain.length-1; i>=0; i--)
			{
				plain[i] = charsetFixed[i][(int)(index%charsetFixed[i].length)];
				index /= charsetFixed[i].length;
			}
		}
		else if(PermutedCharset)
		{
			List<byte[]> plain = new LinkedList<byte[]>();
			int length = 0;
			for(int i=0; i<charset.length; i++)
			{
				plain.add(primaryIndexToPlain(i, index%partPlainSpaceTotal[i]));
				index /= partPlainSpaceTotal[i];
				length += plain.get(i).length;
			}
			this.plain = new byte[length];			
			length = 0;
			for(int i=charset.length; i>1; i--)
			{
				byte[] temp = plain.remove((int)(index%i));
				System.arraycopy(temp, 0, this.plain, length, temp.length);
				length += temp.length;
				index /= i;
			}
			System.arraycopy(plain.get(0), 0, this.plain, length, plain.get(0).length);
		}
		else
		{
			byte[][] plain = new byte[charset.length][];
			int length = 0;
			for(int i=charset.length-1; i>=0; i--)
			{
				plain[i] = primaryIndexToPlain(i, index%partPlainSpaceTotal[i]);
				index /= partPlainSpaceTotal[i];
				length += plain[i].length;
			}
			this.plain = new byte[length];
			length = 0;
			for(byte[] b:plain)
			{
				System.arraycopy(b, 0, this.plain, length, b.length);
				length += b.length;
			}
		}
	}

	byte[] searchTable(long index)
	{
		int head = 1;
		int tail = mixedCharsetTable.length;
		while(head<tail)
		{
			int mid = (head+tail)/2;
			long lastValue = ByteBuffer.wrap(mixedCharsetTable[mid-1], 0, 8).getLong();
			long value = ByteBuffer.wrap(mixedCharsetTable[mid], 0, 8).getLong();			
			if(index>=lastValue && index<value)
			{
				return Arrays.copyOfRange(mixedCharsetTable[mid], 8, mixedCharsetTable[mid].length);
			}
			else if(index<lastValue)
			{
				tail = mid;
			}
			else head = mid+1;
		}
		return null;
	}
	
	int[] getCombinationOrder(int k, int n, int no)
	{
        int[] array = new int[k];
        for(int i=0; i<k; i++) array[i] = i;
        for(int i=0; i<no; i++)
        {
            int num = k-1;
            while(array[num]==num+n-k) num--;
            array[num]++;
            for(int j=num+1; j<k; j++)
            {
                array[j] = array[j-1]+1;
            }
        }		
        return array;
	}
	
	void indexToPlain_Mixed()
	{
		//table lookup for getting the plain length of each charset
		byte[] plainLength = searchTable(index);
		int[] plainLengthTotal = new int[plainLength.length-1];
		plainLengthTotal[plainLengthTotal.length-1] = plainLength[plainLengthTotal.length]+plainLength[plainLengthTotal.length-1];
		for(int i=plainLengthTotal.length-2; i>=0; i--)
		{
			plainLengthTotal[i] = plainLengthTotal[i+1]+plainLength[i];
		}
		
		//fill in the plain
		plain = new byte[plainLengthTotal[0]];
		for(int i=0; i<plainLength.length-1; i++)
		{
			int com = RainbowCalcTools.combination(plainLength[i], plainLengthTotal[i]);
			int[] order = getCombinationOrder((int)plainLength[i], plainLengthTotal[i], (int)(index%com));
			index /= com;
			for(int j=order.length-1; j>=0; j--)
			{
				int pos = 0;
				int count = 0;
				while(count<order[j] || plain[pos]!=0)
				{
					if(plain[pos]==0) count++;
					pos++;
				}
				plain[pos] = charset[i][(int)(index%charset[i].length)];
				index /= charset[i].length;
			}
		}
		for(int i=plain.length-1; i>=0; i--) //fill in the last plain part whose position order is fixed
		{
			if(plain[i]==0)
			{
				plain[i] = charset[plainLength.length-1][(int)(index%charset[plainLength.length-1].length)];
				index /= charset[plainLength.length-1].length;
			}
		}
 	}
	
	void plainToHash() throws NoSuchAlgorithmException, IllegalArgumentException, UnsupportedEncodingException {
		if(alg.equalsIgnoreCase("ntlm")) 
		{
			hash = NTLM.computeNTPassword(new String(plain, "UTF-8"));
		}
		else
			hash = digest.digest(plain);
	}

	void hashToIndex(int npos) {
		long low = (hash[0] & 0xff) + ((hash[1] & 0xff) << 8)
				+ ((long) (hash[2] & 0xff) << 16)
				+ ((long) (hash[3] & 0xff) << 24)
				+ ((long) (hash[4] & 0xff) << 32)
				+ ((long) (hash[5] & 0xff) << 40)
				+ ((long) (hash[6] & 0xff) << 48);
		long high = (long) (hash[7] & 0xff);
		long twoTo56Remainder = (1L << 56) % plainSpaceTotal;
		index = (low + twoTo56Remainder * high + npos + (tableIndex << 16)) % plainSpaceTotal;
	}

	long getIndex(long startIndex, int startPos, int endPos) throws NoSuchAlgorithmException, IllegalArgumentException, UnsupportedEncodingException
	{
		index = startIndex;
		for(int pos = startPos; pos < endPos; pos++)
		{
			indexToPlain();
			plainToHash();
			hashToIndex(pos);
		}
		return index;
	}
	
	long getIndex(byte[] startHash, int startPos, int endPos) throws NoSuchAlgorithmException, IllegalArgumentException, UnsupportedEncodingException
	{
		if(startPos==endPos) return 0;
		hash = new byte[startHash.length];
		hash = startHash.clone();
		for(int pos = startPos; pos < endPos-1; pos++)
		{
			hashToIndex(pos);
			indexToPlain();
			plainToHash();
		}
		hashToIndex(endPos-1);
		return index;
	}
	
	String getPlain(long index)
	{
		this.index = index;
		indexToPlain();
		return new String(this.plain);
	}
	
	byte[] check(long startIndex, int pos, byte[] hash) throws NoSuchAlgorithmException, IllegalArgumentException, UnsupportedEncodingException
	{
		index = startIndex;
		indexToPlain();
		for(int i=0; i<pos; i++)
		{
			plainToHash();
			hashToIndex(i);
			indexToPlain();
		}
		plainToHash();
		byte[] trimedHash = new byte[this.hash.length];
		System.arraycopy(hash, 0, trimedHash, 0, this.hash.length);
		return Arrays.equals(this.hash, trimedHash)?plain:null;
	}

	public long[][] getRainbowTable(int chainLen, int chainCnt, boolean sort, boolean perfect) throws NoSuchAlgorithmException, IllegalArgumentException, UnsupportedEncodingException
	{
		HashSet<Long> set = new HashSet<Long>();
		long[][] rainbowTable = new long[chainCnt][2];
		long start = -1;
		for(int i=0; i<chainCnt; i++)
		{
			long end;
			do
			{
				end = getIndex(++start, 0, chainLen-1);
			}
			while(set.contains(end));
			if(perfect) set.add(end);
			rainbowTable[i][0] = start;
			rainbowTable[i][1] = end;
		}
		if(sort) RainbowTableGeneration.quickSort(rainbowTable, 0, rainbowTable.length-1);
		return rainbowTable;
	}
	
	public String recover(long[][] rainbowTable, int chainLen, String hash) throws NoSuchAlgorithmException, IllegalArgumentException, UnsupportedEncodingException
	{
		byte[] hashByte = RainbowCalcTools.hashStringToByteArray(hash);
		int totalAlert = 0;
		int trueAlert = 0;
		for(int i=chainLen-2; i>=0; i--)
		{
			long endpoint = getIndex(hashByte, i, chainLen-1);
			long[] index = RainbowCrack.binarySearch(rainbowTable, endpoint); 
			if(index!=null)
			{
				totalAlert += index.length;
//				System.out.println("Found "+index.length+" alert at column "+i+", endPoint: "+endpoint);
				for(long l:index)
				{
					byte[] plain = check(l, i, hashByte);
					if(plain!=null)
					{
						System.out.println("Plain: "+new String(plain));
						trueAlert++;
//						return new String(plain);
					}
				}
			}
		}
		System.out.println("Total number of (false) alerts: "+(totalAlert-trueAlert)+"/"+totalAlert);
		return null;
	}
	
	public void showMatrix(long[][] rainbowTable, int chainLen) throws NoSuchAlgorithmException, IllegalArgumentException, UnsupportedEncodingException
	{
		long chainCnt = rainbowTable.length;
		for(int i=0; i<chainCnt; i++)
		{
			System.out.printf("%3s ", this.getPlain(rainbowTable[i][0]));
			for(int j=1; j<chainLen; j++)
			{
				long index = this.getIndex(rainbowTable[i][0],0,j);
				System.out.printf("%3s ", this.getPlain(index));
			}
			System.out.println();
		}		
	}
	
	public static void main(String args[]) throws Exception
	{
		RainbowChainWalk[] rcw = new RainbowChainWalk[10];
		rcw[0] = new RainbowChainWalk("ntlm","mixalpha-numeric-all#1-9",0);
		rcw[1] = new RainbowChainWalk("ntlm","[loweralpha#2#numeric#2#symbol#2#alpha#2]",0);
		rcw[2] = new RainbowChainWalk("ntlm","[loweralpha#2#numeric#3-4#symbol#1#alpha#2]",0);
		rcw[3] = new RainbowChainWalk("ntlm","[loweralpha#3#numeric#3-4#symbol#1#alpha#1]",0);
		rcw[4] = new RainbowChainWalk("ntlm","[loweralpha#3#numeric#1#symbol#1#alpha#3]",0);
		rcw[5] = new RainbowChainWalk("ntlm","mixalpha-numeric-all#1-9",0);
		rcw[6] = new RainbowChainWalk("ntlm","[loweralpha#1#numeric#1-6#symbol#1#alpha#1]",0);
		rcw[7] = new RainbowChainWalk("ntlm","(loweralpha#2-3#numeric#3-4#symbol#1#alpha#1)",0);
		rcw[8] = new RainbowChainWalk("ntlm","(loweralpha#1-3#numeric#1#symbol#1#alpha#2-3)",0);
		rcw[9] = new RainbowChainWalk("ntlm","(loweralpha#4#numeric#1-3#symbol#1#alpha#1)",0);
		//		for(int i=0; i<54000; i++)
//		{
//			System.out.println(rcw[4].getPlain(i));
//		}
		int chainLen = 20309;
		long chainCnt = 10999796900l;
		long start = System.currentTimeMillis();
		
//		System.out.println((double)17400*1050000000/100000000l/3600);
//		long[][] rainbowTable = RainbowCrack.loadRainbowTable("ntlm_alpha#1-2#numeric#1-3_0_1000x20000.rtE");
//		long[][] rainbowTable = rcw.getRainbowTable(chainLen, chainCnt, true, false);
//		rcw.showMatrix(rainbowTable, chainLen);
		
		for(int i=0; i<10; i++)
		System.out.println("TotalSpace: "+rcw[i].plainSpaceTotal+" "+new DecimalFormat("0.00E0").format(rcw[i].plainSpaceTotal));
//		System.out.println("WorkFactor: "+(double)(chainLen-1)*chainCnt/rcw.plainSpaceTotal);
//		System.out.println("ExpectedUniqueChains: "+chainCnt/((double)(chainLen-1)*chainCnt/rcw.plainSpaceTotal/2+1));
//		System.out.println("Success Rate: "+RainbowCalcTools.successRate2(rcw.plainSpaceTotal, chainCnt, chainLen, 1));
	
		String hash = "41E184179CF53EC4D2CCF08950226A4B";
//		rcw.recover(rainbowTable, chainLen, hash);
//		int count = 0;
//		BufferedReader file = new BufferedReader(new FileReader("ntlm_hash_numeric#3#loweralpha#0-1.txt"));
//		String hash = file.readLine();
//		while(hash!=null){
//			String plain = rcw.recover(rainbowTable, chainLen, hash);
//			if(plain!=null) 
//				{
//				System.out.println("Plain: "+plain);
//				count++;
//				}
//		hash = file.readLine();
//		}
//		System.out.println(count);

//		RainbowTableGeneration.rainbowTableGenerate("md5", "loweralpha#2#numeric#2", 5, 200, 200);
//		RainbowCrack.rainbowCrack("md5_loweralpha#2#numeric#2_0_200x200.rtE", "md5Hash.txt");
//		RainbowCrack.rainbowCrack("md5_loweralpha#2#numeric#2_1_200x200.rtE", "md5Hash.txt");
//		RainbowCrack.rainbowCrack("md5_loweralpha#2#numeric#2_2_200x200.rtE", "md5Hash.txt");
//		RainbowCrack.rainbowCrack("md5_loweralpha#2#numeric#2_3_200x200.rtE", "md5Hash.txt");
//		RainbowCrack.rainbowCrack("md5_loweralpha#2#numeric#2_4_200x200.rtE", "md5Hash.txt");
	
//		System.out.println("time: "+(System.currentTimeMillis()-start));
		
//		int uniqueChain = 1;
//		for(int i=1; i<rainbowTable.length; i++)
//		{
//			if(rainbowTable[i-1][1]!=rainbowTable[i][1])
//			{	
//				uniqueChain++;
//			}
//		}
//		System.out.println("UniqueChains: "+uniqueChain);
//		System.out.println("UniqueChainsPercentage: "+(float)uniqueChain/chainCnt);
		
		System.out.println("time: "+(System.currentTimeMillis()-start));
	}

}


