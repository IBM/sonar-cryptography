package com.ibm.example; 

public class DuplicateParametersFinding2TestFile {

    public class Car {
        Car(SeatInterface frontSeats, SeatInterface backSeats) {}
    }
    public interface SeatInterface {}
    public class LeatherSeats implements SeatInterface {}
    public class HeatedSeats implements SeatInterface {}

    public void test() {
        Car myCar = new Car(new LeatherSeats(), new HeatedSeats()); // Noncompliant {{Car}}
    }
}
