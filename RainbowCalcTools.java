import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;


public class RainbowCalcTools {
	public static long expectedUniqueChains(long totalSpace, long chainCnt, int count)
	{
		double ret = (double)chainCnt;
//		double miss = 1-(double)1/totalSpace;
		for(int i=0; i<count; i++)
		{
//			ret = totalSpace*(1-Math.pow(miss, ret));
			ret = totalSpace*(1-Math.exp(-ret/totalSpace));
		}
		return (long)ret;
	}
	
	public static double successRate(long totalSpace, long chainCnt, int chainLen, int tables)
	{
		double euc = (double)chainCnt;
		double miss = 1;
		for(int i=0; i<chainLen-1; i++)
		{
			miss *= 1-euc/totalSpace;
			euc = totalSpace*(1-Math.exp(-euc/totalSpace));
		}	
		return 1-Math.pow(miss, tables);
	}
	
	public static double successRate2(long totalSpace, long chainCnt, int chainLen, int tables)
	{
		return 1-Math.pow(2/(2+(double)chainCnt*(chainLen-1)/totalSpace), 2*tables);
	}
	
	public static long next(FileInputStream in) throws IOException {
		byte[] tmp = new byte[8];
		in.read(tmp);
		long x = (tmp[0] & 0xff) + ((tmp[1] & 0xff) << 8);
		x += ((long) (tmp[2] & 0xff) << 16) + ((long) (tmp[3] & 0xff) << 24);
		x += ((long) (tmp[4] & 0xff) << 32) + ((long) (tmp[5] & 0xff) << 40);
		x += ((long) (tmp[6] & 0xff) << 48) + ((long) (tmp[7] & 0xff) << 56);
		return x;
	}

	public static String byteToStr(byte[] bytes)
			throws UnsupportedEncodingException {
		return new String(bytes, "UTF-8");
	}

	public static String byteToHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < bytes.length; i++) {
			sb.append(Character.forDigit((bytes[i] & 240) >> 4, 16));
			sb.append(Character.forDigit(bytes[i] & 15, 16));
		}
		return sb.toString();
	}
	
	public static byte[] hashStringToByteArray(String hash)
	{
		byte[] hashByte = new byte[hash.length()/2];
		for(int i = 0; i<hash.length()/2; i++)
		{
			hashByte[i] = (byte)Integer.parseInt(hash.substring(i*2,i*2+2),16);
//			hashByte[i] = Integer.valueOf(hash.substring(i*2,i*2+2),16).byteValue(); //alternative
		}
		return hashByte;
	}
	
	public static void createConfig(String rainbowTable, String configFileName, String ip) throws IOException
	{
		File file = new File(rainbowTable);
		if(!file.exists()) return;
		FileWriter writer; 
		if(file.isDirectory())
		{
			writer = new FileWriter(new File(rainbowTable+File.separator+configFileName));
			String[] files = file.list();
			for(String s:files)
			{
				if(s.endsWith(".rtE")||s.endsWith(".rt"))
				{
					String[] split = s.split("_");
					String rainbow = split[0]+"_"+split[1]+"_0_"+split[3].split("\\.")[0];
					writer.write(rainbow+"%"+s+"="+ip+"\r\n");
				}
			}
		}
		else
		{
			writer = new FileWriter(new File(configFileName));	
			String s = file.getName();
			if(s.endsWith(".rtE")||s.endsWith(".rt"))
			{
				String[] split = s.split("_");
				String rainbow = split[0]+"_"+split[1]+"_0_"+split[3].split(".")[0];
				writer.write(rainbow+"%"+s+"="+ip+"\n");
			}
		}			
		writer.close();
	}
	
	public static double Rtc_Rmsc(double Rmsc, int l)
	{
		double a = Math.pow(l, 3)/(2*l+1)/(2*l+2)/(2*l+3);
		double b = ((2*l-1)+(2*l+1)*Rmsc)*Math.pow(2+Rmsc, 2);
		double c = 4*((2*l-1)+l*(2*l+3)*Rmsc)*Math.pow(2/(2+Rmsc), 2*l);
		return a*(b-c);
	}
	
	public static double T_hr(double Rmsc, int l)
	{
		double a = l/((2*l+1)*(2*l+2)*(2*l+3)*Rmsc*Rmsc);
		double b = ((2*l-1)+(2*l+1)*Rmsc)*Math.pow(2+Rmsc, 2);
		double c = 4*((2*l-1)+l*(2*l+3)*Rmsc)*Math.pow(2/(2+Rmsc), 2*l);
		return a*(b-c);
	}
	
	public static double T_lookup(double Rmsc, int l)
	{
		double a = 2+Rmsc-2*Math.pow(2/(2+Rmsc), 2*l);
		return a/(2*l+1)/Rmsc;
	}
	
	public static double Rtc_Rps(double Rps, int l)
	{
		double a = (double)4*l*l*l/(2*l+1)/(2*l+2)/(2*l+3);
		double b = (-(2*l+3)+2*(2*l+1)*Math.pow(1-Rps, -(double)1/2/l))*Math.pow(1-Rps, -(double)1/l);
		double c = (Math.pow(2*l+1, 2)-2*l*(2*l+3)*Math.pow(1-Rps, -(double)1/2/l))*(1-Rps);
		return a*(b+c);
	}
	
	//the count of alarms one hash may have in l rainbow tables
	public static double alarmCount(double Rmsc, int t, int l)
	{
		return Rmsc/2*(t+3)*l;
	}
	
	//links need to do in checking phase
	public static double checkLinksCount(double Rmsc, int l, int t)
	{
		return Rmsc*l/6*t*t;
	}
	
	public static double Rps_perfect(long N, long m, int t)
	{
		return 1-Math.pow(Math.exp(-(double)m/N), t);
	}
	
	public static int combination(int m, int n)
	{
		if(m>n)
		{
			m ^= n;
			n ^= m;
			m ^= n;
		}
		long ret = 1;
		for(int i=0; i<m; i++)
		{
			ret *= n--;
			ret /= i+1;
		}
		return (int)ret;
	}
	
	public static long factorial(byte n)
	{
		long ret = 1;
		for(int i=2; i<=n; i++) ret *= i;
		return ret;
	}
	
	public static double Rpc(double Rps, int l)
	{
		return 2*l*Math.pow(1-Rps, -(double)1/2/l)-2*l;
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException
	{
//		System.out.println(successRate(10000, 1, 30000, 1));
//		System.out.println(successRate2(10000, 1, 30000, 1));
//		RainbowChainWalk rcw = new RainbowChainWalk("md5", "loweralpha#6#numeric#3", 0);
		for(double i=0.5; i<1; i+=(double)1/64)
		{
//			double i = 0.785;
			System.out.println(Rpc(i, 1));
		}
	}
}
