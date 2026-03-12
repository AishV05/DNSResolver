package com.ayushman.dns.protocol;
import java.util.List;
public class DnsMessage{
    private final DnsHeader header;
    private final List<DnsQuestion> questions;
    private final List<DnsRecord> answers;

    public DnsMessage(DnsHeader header, List<DnsQuestion> questions, List<DnsRecord> answers){
        this.header = header;
        this.questions = questions;
        this.answers = answers;
    }
    public DnsHeader header(){
        return header;
        }
    public List<DnsQuestion> questions(){
        return questions;
    }
    public List<DnsRecord> answers(){
        return answers;
    }
}