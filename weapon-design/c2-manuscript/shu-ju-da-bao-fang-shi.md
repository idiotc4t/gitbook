# 数据打包DataPacker

![](../../.gitbook/assets/image%20%28290%29.png)

```text
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace xxx.Core
{
    class DataPacker
    {
        byte[] buffer = new byte[] { };
        int size = 0;
        public DataPacker(byte[] data)
        {
            size = BitConverter.ToInt32(data[..3]);
            buffer = data[4..];
        }
        public DataPacker()
        {
        }
        public byte[] sub(int start,int end)
        {
            return buffer[start..end];
        }
        public void push(int data)
        {
            var dataBytes = BitConverter.GetBytes(data);
            buffer = Utils.Combine(buffer, dataBytes);
        }
        public void push(short data)
        {
            var dataBytes = BitConverter.GetBytes(data);
            buffer = Utils.Combine(buffer, dataBytes);
        }
        public void push(string data)
        {
            var sizeBytes = BitConverter.GetBytes(data.Length + 1);
            var dataBytes = Encoding.ASCII.GetBytes(data);
            buffer = Utils.Combine(buffer, sizeBytes, dataBytes, new byte[] { 0x00 });
        }
        public void push(byte data)
        {
            buffer = Utils.Combine(buffer, new byte[] { data});
        }

        public void push(byte[] data)
        {
            var dataBytes = BitConverter.GetBytes(data.Length);
            buffer = Utils.Combine(buffer, dataBytes, data);
        }
        public byte[] GetBuffer()
        {
            var dataBytes = BitConverter.GetBytes(buffer.Length+4);
            return (byte[])Utils.Combine(dataBytes, buffer).Clone();
        }

    }
}

```

