package com.example;

import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.ProducerConfig;
import java.util.Collections;
import java.util.Properties;
public class Admin {
  private final static String BOOTSTRAP_SERVERS = "172.19.1.11:9092";
  //private final static String BOOTSTRAP_SERVERS = "localhost:9092";
  public static Properties getProducerProps() {
    Properties props = new Properties();
    props.put("bootstrap.servers", BOOTSTRAP_SERVERS);
    props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    props.put(ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG,"10000");
    props.put(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG,"3000");
    props.put(ProducerConfig.MAX_BLOCK_MS_CONFIG,"10000");
    props.put(ProducerConfig.TRANSACTION_TIMEOUT_CONFIG,"1000");
    props.put(ProducerConfig.RECONNECT_BACKOFF_MAX_MS_CONFIG,"1000");
    props.put(ProducerConfig.SOCKET_CONNECTION_SETUP_TIMEOUT_MS_CONFIG,"500");
    props.put(ProducerConfig.SOCKET_CONNECTION_SETUP_TIMEOUT_MAX_MS_CONFIG,"1000");
    props.put(ProducerConfig.ACKS_CONFIG,"all");
    props.put(ProducerConfig.RETRIES_CONFIG,"1000");
    
    // props.put("acks","all");
    // props.put("retries","1000");
    props.put("isolation-level","read_commited");
    props.put("enable.idempotence",true);
    return props;
  }
  public static Properties getConsumerProps(String groupId) {
    Properties props = new Properties();
    props.put("bootstrap.servers", BOOTSTRAP_SERVERS);
    props.put("group.id", groupId);
    props.put("key.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
    props.put("value.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
    props.put("socket.connection.setup.timeout.ms","1000");
    props.put("socket.connection.setup.timeout.max.ms","500");
    props.put(ConsumerConfig.METADATA_MAX_AGE_CONFIG,"60000");
    props.put(ConsumerConfig.REQUEST_TIMEOUT_MS_CONFIG,"10000");
    props.put(ConsumerConfig.DEFAULT_API_TIMEOUT_MS_CONFIG,"10000");
    props.put(ConsumerConfig.HEARTBEAT_INTERVAL_MS_CONFIG,"300");
    props.put(ConsumerConfig.SESSION_TIMEOUT_MS_CONFIG,"6000");
    props.put(ConsumerConfig.CONNECTIONS_MAX_IDLE_MS_CONFIG,"60000");
    props.put(ConsumerConfig.ISOLATION_LEVEL_CONFIG,"read_committed");
    props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG,"earliest");
    props.put(ConsumerConfig.FETCH_MIN_BYTES_CONFIG,"1024");
    return props;
  }
  public static boolean topicsExists() {
    Properties props = new Properties();
    props.put(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, BOOTSTRAP_SERVERS);
    boolean exist = false;
    for (int i=0;i<5;i++){
      try (AdminClient client = AdminClient.create(props)) {
        exist = client.listTopics().names().get().contains(Integer.toString(i));
        if (!exist){
          return exist;
        }
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }
    return exist;
  }
  public static void createTopics() {
    Properties props = new Properties();
    props.put(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, BOOTSTRAP_SERVERS);
    for (int i=0;i<5;i++){
      try (AdminClient client = AdminClient.create(props)) {
        NewTopic newTopic = new NewTopic(Integer.toString(i), 20, (short) 3);
        client.createTopics(Collections.singletonList(newTopic));
      } catch (Exception e) {
          throw new RuntimeException(e);
      }
      }
    }
}