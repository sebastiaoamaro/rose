package com.example;

import java.util.Random;
import java.util.Scanner;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Collection;

public class Main {
  public static void main(String[] args) {

    if (!Admin.topicsExists()) {
      Admin.createTopics();
    }
    System.out.print("Created topics\n");
    Collection<String> topics = new ArrayList<String>();

    for(int i = 0; i<5;i++){
      topics.add(Integer.toString(i));
    }
    ExecutorService executorService = Executors.newSingleThreadExecutor();
    try (ChatConsumer consumer = new ChatConsumer(topics, UUID.randomUUID().toString());
          ChatProducer producer = new ChatProducer(topics)) {
      executorService.execute(consumer);
      System.out.print("Connected, press Ctrl+C to exit\n");
      run_workload(producer);
    } catch (Exception e) {
        System.out.println("Closing client...");
    } finally {
        executorService.shutdownNow();
    }
  }

  public static void run_workload(ChatProducer producer){
    HashMap<Integer, Integer> Map = new HashMap<Integer, Integer>();
    Map.put(0,0);
    Map.put(1,0);
    Map.put(2,0);
    Map.put(3,0);
    Map.put(4,0);

    Random rand = new Random(); 

    for(int i = 0;i<5000000;i++){
      Integer topic = rand.nextInt(5);
      Integer value = Map.get(topic);
      value = value +1;
      producer.sendMessage( topic , Integer.toString(value));
      Map.put(topic,value);

      if(i%10000 == 0){
        System.out.println("Making Progress " + i);
      }
    }
  }
}
