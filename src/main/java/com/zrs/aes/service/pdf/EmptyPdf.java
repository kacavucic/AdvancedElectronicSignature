package com.zrs.aes.service.pdf;

// let us import all required packages

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;

public class EmptyPdf {

    public static void main(String args[]) throws Exception
    {
        // Creating a PdfWriter to C:/example.pdf
        String path = "C:/example.pdf";
        PdfWriter writer = new PdfWriter(path);

        // Creating a PdfDocument object
        PdfDocument pdf = new PdfDocument(writer);

        // Creating a Document object
        Document document = new Document(pdf);

        // to check if its created or not
        System.out.println("Your PDF has been created");
    }
}
