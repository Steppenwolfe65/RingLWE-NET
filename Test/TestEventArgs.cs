using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Test
{
    public class TestEventArgs : EventArgs
    {
        public TestEventArgs(string Message)
        {
            this.Message = Message;
        }

        public string Message { get; set; }
        public int TestCount { get; set; }
    }
}
