import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.security.NoSuchAlgorithmException;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;


public class RainbowCrack {
	public static long[] binarySearch(long[][] r, long target)
	{
		if(r==null) return null;
		int head = 0;
		int tail = r.length-1;
		while(head<=tail)
		{
			if(r[(head+tail)/2][1]==target || head==tail)
			{
				head = tail = (head+tail)/2;
				break;
			}
			else if(target<r[(head+tail)/2][1])
			{
				tail = (head+tail)/2-1;
			}
			else 
				head = (head+tail)/2+1;
		}
		if(r[head][1]!=target) return null;
		while(head>=0 && r[head][1]==target) head--;
		while(tail<r.length && r[tail][1]==target) tail++;
		long[] ret = new long[tail-head-1];
		for(int i=0; i<ret.length; i++)
		{
			ret[i] = r[++head][0];
		}
		return ret;
	}
	
	public static long[][] loadRainbowTable(String file) throws IOException
	{
		long time = System.currentTimeMillis();
		FileInputStream in = new FileInputStream(file);
		FileChannel channel = in.getChannel();
		long length = channel.size();
//		int chainCnt = Integer.parseInt(file.split("_")[3].split("x")[1]);
		int chainCnt = (int)(length/16);
		long[][] ret = new long[chainCnt][2];
	
//		MappedByteBuffer buffer = channel.map(FileChannel.MapMode.READ_ONLY, 0, length);
//		buffer.order(ByteOrder.LITTLE_ENDIAN);
//		for(int i=0; i<ret.length; i++)
//		{
//			//read little endian long data
//			ret[i][0] = buffer.getLong();
//			ret[i][1] = buffer.getLong();
//		}
//		channel.close();

		BufferedInputStream bin = new BufferedInputStream(in);
//		System.out.println(bin.available());
		byte[] buffer = new byte[8];
		for(int i=0; i<ret.length; i++)
		{
			bin.read(buffer);
			ret[i][0] = ByteBuffer.wrap(buffer).order(ByteOrder.LITTLE_ENDIAN).getLong();
			bin.read(buffer);
			ret[i][1] = ByteBuffer.wrap(buffer).order(ByteOrder.LITTLE_ENDIAN).getLong();
		}
		bin.close();
		
//		DataInputStream din = new DataInputStream(in);
//		System.out.println(din.available());		
//		for(int i=0; i<ret.length; i++)
//		{
//			ret[i][0] = Long.reverseBytes(din.readLong());
//			ret[i][1] = Long.reverseBytes(din.readLong());
//		}
//		din.close();
		
		in.close();
		System.out.println("Load "+file+" in "+(System.currentTimeMillis()-time)+"ms.");
		return ret;
	}
	
//	public static String rainbowCrack(String hash, String file)
	public static long[] hashPreCompute(byte[] hash, String alg, String charset, int tableIndex, final int chainLen) throws NoSuchAlgorithmException, IllegalArgumentException, UnsupportedEncodingException
	{
		//progress monitor
		Timer t = new Timer();
		final int[] param = new int[2];
		final int interval = 500;
		final long totalLinks = (long)chainLen*(chainLen-1)/2;
		t.schedule(new TimerTask()
		{
			public void run()
			{
				double percentage = (double)100*(chainLen-1+chainLen-param[0])*param[0]/2/totalLinks;
				int linksSinceLast = (chainLen-1-param[1]+chainLen-param[0])*(param[0]-param[1])/2;
				String info = ""+param[0]+"/"+(chainLen-1)+"   "+new DecimalFormat("##.##").format(percentage)+"%   "+linksSinceLast/((double)interval/1000)+" links/s     ";
				param[1] = param[0];
				System.out.print(info);
//				System.out.println(info.length());
				for(int i=0; i<info.length(); i++) System.out.print("\b");
//				System.out.println();
			}
		}, interval, interval);
		
		RainbowChainWalk rcw = new RainbowChainWalk(alg, charset, tableIndex);
		long[] ret = new long[chainLen-1];
		for(int i=0; i<chainLen-1; i++)
		{
			param[0] = i;
			ret[i] = rcw.getIndex(hash, i, chainLen-1);
//			System.out.println(""+i+"\t"+ret[i]);
		}
		
		t.cancel();
		System.out.println("finished.\t\t\t\t\t");
		return ret;
	}
	
	public static String[] loadHashFile(String filename) throws IOException
	{
		ArrayList<String> hashes = new ArrayList<String>();
		FileReader file = new FileReader(filename);
		BufferedReader reader = new BufferedReader(file);
		String temp = null;
		while((temp = reader.readLine())!= null)
		{
			hashes.add(temp);
		}
		reader.close();
		file.close();
		return hashes.toArray(new String[hashes.size()]);
	}
	
	public static void hashPreComGenerate(String hashFile, String hpcFileName, String alg, String charset, int tableIndex, int chainLen) throws IOException, NoSuchAlgorithmException, IllegalArgumentException
	{
		System.out.println("----------RainbowTablePreCompute---------");
		System.out.println("Output: "+hpcFileName);
		
		File file = new File(hpcFileName);
		if(file.exists())
		{
			System.out.println(hpcFileName+" exists.");
			return;
		}
		String[] hashes = loadHashFile(hashFile);
		if(hashes.length==0)
		{
			System.out.println(hashFile+" is empty.");
			return;
		}
		
		long time = System.currentTimeMillis();
		System.out.println("Started at "+new Date());
			
		BufferedWriter writer = new BufferedWriter(new FileWriter(file));
		for(int i=0; i<hashes.length; i++)
		{
			System.out.print(""+(i+1)+"/"+hashes.length+"\t"+hashes[i]+"\t");
			long[] hashPreComputeIndex = hashPreCompute(RainbowCalcTools.hashStringToByteArray(hashes[i]), alg, charset, tableIndex, chainLen);
			for(int j=0; j<hashPreComputeIndex.length; j++)
			{
//				System.out.println(""+hashPreComputeIndex[j]+"\t"+j+"\t"+hashes[i]);
				writer.write(""+hashPreComputeIndex[j]+"\t"+j+"\t"+hashes[i]);
				writer.newLine();
			}
		}
		writer.close();
		System.out.println("Finished at "+new Date()+"\t Time used: "+(System.currentTimeMillis()-time)/1000+"s.");
	}
	
	public static void lookupRainbowTable(String rainbowTableFile, String hpcFile, String lookupFileName) throws IOException
	{
		System.out.println("----------RainbowTableLookup---------");
		System.out.println("Output: "+lookupFileName);
		System.out.println("Started at "+new Date());
		
		long[][] rainbowTable = loadRainbowTable(rainbowTableFile);
		FileReader file = new FileReader(hpcFile);
		BufferedReader reader = new BufferedReader(file);
		FileWriter file2 = new FileWriter(lookupFileName);
		BufferedWriter writer = new BufferedWriter(file2);
		String line = reader.readLine();
		while(line!=null)
		{
			long index = Long.parseLong(line.split("\t")[0]);
			long[] result = binarySearch(rainbowTable, index);
			if(result!=null)
			{
				for(long l:result)
				{
					writer.write(String.valueOf(l)+"\t"+line.substring(line.indexOf("\t")+1));
					writer.newLine();
				}
			}
			line = reader.readLine();
		}
		reader.close();
		file.close();
		writer.close();
		file2.close();
		System.out.println("Finished at "+new Date());
	}
	
	public static void checkHash(String tableLookupFile, String resultFileName, String alg, String charset, int tableIndex, int chainLen) throws NoSuchAlgorithmException, IOException
	{
		System.out.println("----------RainbowTableHashCheck---------");
		System.out.println("Output: "+resultFileName);
		System.out.println("Started at "+new Date());
		
		FileReader file = new FileReader(tableLookupFile);
		BufferedReader reader = new BufferedReader(file);
		FileWriter file2 = new FileWriter(resultFileName, true);
		BufferedWriter writer = new BufferedWriter(file2);
		RainbowChainWalk rcw = new RainbowChainWalk(alg, charset, tableIndex);
		String line = reader.readLine();
		int count = 1;
		while(line!=null)
		{
			if(count%1000==0) System.out.print(""+count+"\t"+line+"\r");
			count++;
			String[] split = line.split("\t");
			byte[] plain = rcw.check(Long.parseLong(split[0]), Integer.parseInt(split[1]), RainbowCalcTools.hashStringToByteArray(split[2]));
			if(plain!=null)
			{
				System.out.println(split[2]+": "+new String(plain)+"\t\t\t");
				writer.write(split[2]+"\t"+new String(plain));
				writer.newLine();
				writer.flush();
			}
			line = reader.readLine();
		}
		reader.close();
		file.close();
		writer.close();
		file2.close();
		System.out.println("Finished at "+new Date()+"\t\t\t");
	}
	
	public static void rainbowCrack(String rainbowTableFile, String hashFile) throws NoSuchAlgorithmException, IllegalArgumentException, IOException
	{
		String[] split = rainbowTableFile.split("_");
		String alg = split[0];
		String charset = split[1];
		int tableIndex = Integer.parseInt(split[2]);
		int chainLen = Integer.parseInt(split[3].split("x")[0]);
		String hpcFileName = hashFile+"."+alg+"_"+charset+"_"+tableIndex+"_"+chainLen+".hpc";
		String lookupFileName = hpcFileName+".lookup";
		
		hashPreComGenerate(hashFile, hpcFileName, alg, charset, tableIndex, chainLen);
		lookupRainbowTable(rainbowTableFile, hpcFileName, lookupFileName);
		checkHash(lookupFileName, hashFile+".result", alg, charset, tableIndex, chainLen);
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, IllegalArgumentException, IOException, InterruptedException
	{
		rainbowCrack("md5_loweralpha#6#numeric#3_0_60000x14121284_0.rtE", "hash_loweralpha#6#numeric#3.txt");
//		RainbowCalcTools.createConfig("E:\\FTP", "config2.txt", "192.168.217.1");
//		System.out.println(Long.toHexString(44));
	}
}
