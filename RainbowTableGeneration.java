import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.text.DateFormat;
import java.util.Date;
import java.util.LinkedList;
import java.util.Timer;
import java.util.TimerTask;


public class RainbowTableGeneration {
	public static void quickSort(long[][] r, int head, int tail)
	{
		if(head>=tail) return;
		long lebal = r[head][1];
		int h = head;
		int t = tail;
		long[] temp = new long[2];
		while(h<t)
		{
			while(h<t && r[t][1]>=lebal) t--;
			temp[0] = r[h][0];
			temp[1] = r[h][1];
			r[h][0] = r[t][0];
			r[h][1] = r[t][1];
			r[t][0] = temp[0];
			r[t][1] = temp[1];			
			while(h<t && r[h][1]<=lebal) h++;
			temp[0] = r[h][0];
			temp[1] = r[h][1];
			r[h][0] = r[t][0];
			r[h][1] = r[t][1];
			r[t][0] = temp[0];
			r[t][1] = temp[1];
		}
		quickSort(r,head,h-1);
		quickSort(r,t+1,tail);
	}
	
	public static void rainbowTableGenerate(final String alg, final String charset, final int tableCnt, final int chainLen, final long chainCnt, final int threads) throws Exception
	{		
		System.out.println("----------RainbowTableGenerate---------");
		System.out.println("Started at "+new Date());
		final int[] param = new int[3];
		Timer t = new Timer();
		final int interval = 5000;
		final DateFormat time = DateFormat.getTimeInstance();
		t.schedule(new TimerTask()
		{
			public void run()
			{
				if(param[1]<param[2]) param[2] -= chainCnt;
				System.out.println(time.format(new Date())+"\t"+alg+"_"+charset+"_"+param[0]+"_"+chainLen+"x"+chainCnt+".rtE\t"+param[1]+"/"+chainCnt+"\t"+(param[1]-param[2])*chainLen/(interval/1000)+" links/s"+"\t"+String.format("%.2f", (double)(param[0]*chainCnt+param[1])*100/(chainCnt*tableCnt))+"%");
				param[2] = param[1];
			}
		}, interval, interval);
		
		class GenThread implements Runnable
		{
			int tableIndex;
			int number;
			BufferedOutputStream out;
			GenThread(int tableIndex, int threadNumber, BufferedOutputStream out)
			{
				this.tableIndex = tableIndex;
				this.number = threadNumber;
				this.out = out;
			}
			public void run()
			{
				try {
					RainbowChainWalk rcw = new RainbowChainWalk(alg, charset, tableIndex);
					for(long i=number; i<chainCnt; i+=threads)
					{
						long endpoint = rcw.getIndex(i,0,chainLen-1);
						synchronized(out)
						{
							out.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(i).array());
							out.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(endpoint).array());
						}
						param[1]++;
					}
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}	
		
		LinkedList<Thread> list = new LinkedList<Thread>();
		BufferedOutputStream out;
		for(int tableIndex=0; tableIndex<tableCnt; tableIndex++)
		{
			param[0] = tableIndex;
			param[1] = 0;
			out = new BufferedOutputStream(new FileOutputStream(alg+"_"+charset+"_"+tableIndex+"_"+chainLen+"x"+chainCnt+".rtE", true));
			for(int i=0; i<threads; i++)
			{
				Thread thread = new Thread(new GenThread(tableIndex, i, out));
				thread.start();
				list.add(thread);
			}
			boolean allThreadsFinished = false;
			while(!allThreadsFinished)
			{
				allThreadsFinished = true;
				for(Thread thread:list)
				{
					allThreadsFinished &= !thread.isAlive();
				}
				Thread.sleep(100);
			}
			out.close();
			list.clear();
		}
		System.out.println("Finished at "+new Date());
		t.cancel();
	}
	
	public static void main(String[] args) throws Exception
	{
//		RainbowChainWalk rcw = new RainbowChainWalk("ntlm", "alpha#1#numeric#3#loweralpha#1#all#1", 0);
//		System.out.println(RainbowCalcTools.successRate2(rcw.plainSpaceTotal, 20000, 5000, 4));
		rainbowTableGenerate("ntlm", "alpha-numeric-space#0-8", 1, 1000, 80000, 3);
	}
}
