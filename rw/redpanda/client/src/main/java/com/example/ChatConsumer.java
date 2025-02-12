package com.example;

import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.util.Map;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;

public class ChatConsumer implements Runnable, AutoCloseable {
  private volatile boolean running = true;
  private KafkaConsumer<String, String> consumer;
  private Gson gson;
  private Type type;
  public ChatConsumer(Collection<String> topics, String groupId) {
    this.consumer = new KafkaConsumer<>(Admin.getConsumerProps(groupId));
    this.consumer.subscribe(topics);
    this.gson = new Gson();
    this.type = new TypeToken<Map<String, String>>(){}.getType();
  }
  @Override
  public void run() {
    HashMap<Integer, ArrayList<Integer>> Map = new HashMap<Integer, ArrayList<Integer>>();

    Map.put(0,new ArrayList<Integer>());
    Map.put(1,new ArrayList<Integer>());
    Map.put(2,new ArrayList<Integer>());
    Map.put(3,new ArrayList<Integer>());
    Map.put(4,new ArrayList<Integer>());
    int i = 0;
    while (running) {
      //synchronized (consumer){
      //   System.out.println("Waiting for consumer records");
      //   try {
      //     consumer.wait();
      //   } catch (InterruptedException e) {
      //     // TODO Auto-generated catch block
      //     e.printStackTrace();
      //   }
      // }
      // System.out.println("Found consumer records");

      ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(1000));
      if (records.count() < 10){
        //System.out.println("Records count is " + records.count());
        continue;
      }
      //System.out.println("Have at least 10 records");

      for (ConsumerRecord<String, String> record : records) {
        Map<String, String> messageMap = gson.fromJson(record.value(), type);
        //System.out.println("Topic" +record.topic() + messageMap.get("value"));
        Integer value = Integer.parseInt(messageMap.get("value"));
        Integer topic = Integer.parseInt(record.topic());

        ArrayList<Integer> list = Map.get(topic);
        //System.out.println(Arrays.toString(list.toArray()));

        if (list.contains(value)){
          System.out.println("Duplicate" + " topic " + topic + " value " + value);
          continue;
        }
        list.add(value);
        Map.put(topic,list);
        
        if(i%10000 == 0){
          System.out.println("Making Progress in Consumer");
        }
        i++;

      }
    }
  }
  @Override
  public void close() {
    running = false;
    consumer.close();
  }
}
