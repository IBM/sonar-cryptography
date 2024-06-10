/*
 * SonarQube Cryptography Plugin
 * Copyright (C) 2024 IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package com.ibm.example;

public class DetectionRuleMatchingExactTypesExceptParametersTestFile {

    public interface Thing {
        public void chooseShape(Shape shape);
    } 

    public class Computer implements Thing {
        public void chooseShape(Shape shape) {}
    }

    public class Vehicle implements Thing {
        public void chooseShape(Shape shape) {}
    }

    public class Car extends Vehicle {}

    public class Boat extends Vehicle {}

    public class Shape {}

    public class Circle extends Shape {}

    public class Rectangle extends Shape {}

    public void test() {
        Vehicle v = new Vehicle();
        v.chooseShape(new Shape()); // Noncompliant {{chooseShape}}
        v.chooseShape(new Circle());
        v.chooseShape(new Rectangle());
        Car c = new Car();
        c.chooseShape(new Shape()); // Noncompliant {{chooseShape}}
        c.chooseShape(new Circle());
        c.chooseShape(new Rectangle());
        Boat b = new Boat();
        b.chooseShape(new Shape()); // Noncompliant {{chooseShape}}
        b.chooseShape(new Circle());
        b.chooseShape(new Rectangle());
    }
}
