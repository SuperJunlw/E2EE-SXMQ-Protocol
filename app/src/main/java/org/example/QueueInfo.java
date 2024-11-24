package org.example;


public class QueueInfo {
    private boolean qiSnd;
    private boolean qiNtf;
    private int qiSize;
    private QueueSubInfo qiSub;
    private QueueMsgInfo qiMsg;

    // Getters and toString()
    public boolean isQiSnd() {
        return qiSnd;
    }
    public boolean isQiNtf() {
        return qiNtf;
    }
    public int getQiSize() {
        return qiSize;
    }
    public QueueSubInfo getQiSub() {
        return qiSub;
    }
    public QueueMsgInfo getQiMsg() {
        return qiMsg;
    }
    @Override
    public String toString() {
        return "QueueInfo{" +
                "qiSnd=" + qiSnd +
                ", qiNtf=" + qiNtf +
                ", qiSize=" + qiSize +
                ", qiSub=" + qiSub +
                ", qiMsg=" + qiMsg +
                '}';
    }
    // Nested classes for subscription and message info
    public static class QueueSubInfo {
        private String qSubThread;
        private String qDelivered;
        public String getQSubThread() {
            return qSubThread;
        }
        public String getQDelivered() {
            return qDelivered;
        }
        @Override
        public String toString() {
            return "QueueSubscriptionInfo{" +
                    "qSubThread='" + qSubThread + '\'' +
                    ", qDelivered='" + qDelivered + '\'' +
                    '}';
        }
    }

    public static class QueueMsgInfo {
        private String msgId;
        private long msgTs;
        private String msgType;
        public String getMsgId() {
            return msgId;
        }
        public long getMsgTs() {
            return msgTs;
        }
        public String getMsgType() {
            return msgType;
        }
        @Override
        public String toString() {
            return "QueueMessageInfo{" +
                    "msgId='" + msgId + '\'' +
                    ", msgTs=" + msgTs +
                    ", msgType='" + msgType + '\'' +
                    '}';
        }
    }
}
