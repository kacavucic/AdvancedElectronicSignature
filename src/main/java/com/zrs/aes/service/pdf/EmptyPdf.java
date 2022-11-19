package com.zrs.aes.service.pdf;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;

import java.io.File;
import java.io.FileOutputStream;
import org.apache.poi.xwpf.usermodel.XWPFDocument;

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

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        // Create a blank document
        XWPFDocument xwpfdocument = new XWPFDocument();

        // Create file by specifying the path
        File file = new File("C:/blankdocument.docx");

        // Writing document in file stream
        FileOutputStream ostream
                = new FileOutputStream(file);

        // Write contents to the document
        xwpfdocument.write(ostream);

        // Close the file connection
        ostream.close();
    }
}
