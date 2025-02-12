package com.example;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import com.google.gson.Gson;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.List;

public class ChatProducer implements AutoCloseable {
  private KafkaProducer<String, String> producer;
  private List<String> topics;
  private Gson gson;
  public ChatProducer(Collection topics) {
    this.producer = new KafkaProducer<>(Admin.getProducerProps());
    this.topics= new ArrayList<String>(topics);
    this.gson = new Gson();
  }
  public void sendMessage(Integer topic_index, String value) {
    Map<String, String> messageMap = new HashMap<>();
    messageMap.put("value", value);
    String jsonMessage = gson.toJson(messageMap);
    String topic_string = this.topics.get(topic_index);
    producer.send(new ProducerRecord<>(topic_string, null, jsonMessage));
    producer.flush();
    // try {
    //   // Sleep for 2 seconds (2000 milliseconds)
    //   Thread.sleep(2000);
    //   System.out.println("Slept for 2 seconds");
    // }catch (InterruptedException e) {
    //   // Handle the exception if the thread is interrupted while sleeping
    //   System.out.println("Thread was interrupted");
    // }

  }
  @Override
  public void close() {
    producer.close();
  }
}