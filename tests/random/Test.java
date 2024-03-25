class Test{  
    public static void main(String args[])throws InterruptedException{  
     while(true){
        helper();
        Thread.sleep(1000);
     }  
    }
    
    public static void helper(){
        long pid = ProcessHandle.current().pid();
        System.out.println("Hello Java Pid IS " + Long.toString(pid));  
    }
}