package com.example.auth;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;
import java.util.ArrayList;
import java.util.List;
import javax.swing.text.*;



public class lab {
    private static Set<String> malwareSignatures = new HashSet<>();
    private static List<File> detectedMalwareFiles = new ArrayList<>();
    private JFrame frame;
    private JButton scanButton;
    private JButton deleteButton;
    private JTextPane outputArea;

    static {
        loadMalwareSignatures("E:/Malicious hash/malware_md5_hashes.txt");
    }

    private static void loadMalwareSignatures(String filePath) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                malwareSignatures.add(line.trim());
            }
            System.out.println(malwareSignatures.size() + " Malicious signatures have been loaded.");
        } catch (IOException e) {
            System.out.println("Unable to load malware signature library: " + e.getMessage());
        }
    }

    private static String calculateFileHash(File file) {
        try (FileInputStream fis = new FileInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] byteArray = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(byteArray)) != -1) {
                digest.update(byteArray, 0, bytesRead);
            }
            byte[] hashBytes = digest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static boolean isMalware(File file) {
        String fileHash = calculateFileHash(file);
        return fileHash != null && malwareSignatures.contains(fileHash);
    }

    public static void scanDirectory(String directoryPath, JTextPane outputArea) {
        detectedMalwareFiles.clear();
        Path startPath = Paths.get(directoryPath);
        StyledDocument doc = outputArea.getStyledDocument();
        Style style = outputArea.addStyle("Color Style", null);

        try {
            Files.walkFileTree(startPath, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path filePath, BasicFileAttributes attrs) throws IOException {
                    File file = filePath.toFile();
                    if (isMalware(file)) {
                        StyleConstants.setForeground(style, Color.RED);
                        try {
                            doc.insertString(doc.getLength(), "Malware Detected: " + file.getAbsolutePath() + "\n", style);
                        } catch (BadLocationException e) {
                            e.printStackTrace();
                        }
                        detectedMalwareFiles.add(file);

                        // 显示警告窗口
                        JOptionPane.showMessageDialog(null,
                                "Malware Detected:\n" + file.getAbsolutePath(),
                                "Warning: Malware Detected",
                                JOptionPane.WARNING_MESSAGE);
                    } else {
                        StyleConstants.setForeground(style, Color.WHITE);
                        try {
                            doc.insertString(doc.getLength(), "File Safe: " + file.getAbsolutePath() + "\n", style);
                        } catch (BadLocationException e) {
                            e.printStackTrace();
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            try {
                doc.insertString(doc.getLength(), "Unable to scan directory: " + e.getMessage() + "\n", style);
            } catch (BadLocationException ex) {
                ex.printStackTrace();
            }
        }
    }

    private void deleteDetectedMalware(JTextPane outputArea) {
        if (detectedMalwareFiles.isEmpty()) {
            JOptionPane.showMessageDialog(frame, "No malware files detected or to delete.", "Info", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int confirm = JOptionPane.showConfirmDialog(frame,
                "Are you sure you want to delete all detected malware files?",
                "Confirm Deletion",
                JOptionPane.YES_NO_OPTION);

        if (confirm == JOptionPane.YES_OPTION) {
            for (File malwareFile : detectedMalwareFiles) {
                if (malwareFile.delete()) {
                    appendToPane(outputArea, "Deleted Malware File: " + malwareFile.getAbsolutePath() + "\n", Color.GREEN);
                } else {
                    appendToPane(outputArea, "Failed to Delete File: " + malwareFile.getAbsolutePath() + "\n", Color.YELLOW);
                }
            }
            detectedMalwareFiles.clear();
            JOptionPane.showMessageDialog(frame, "Malware files deleted successfully.", "Deletion Complete", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void appendToPane(JTextPane tp, String msg, Color c) {
        StyledDocument doc = tp.getStyledDocument();
        Style style = tp.addStyle("Color Style", null);
        StyleConstants.setForeground(style, c);
        try {
            doc.insertString(doc.getLength(), msg, style);
        } catch (BadLocationException e) {
            e.printStackTrace();
        }
    }

    public lab() {
        frame = new JFrame("Malware Scanner");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 500);
        frame.setLayout(new BorderLayout());

        outputArea = new JTextPane();
        outputArea.setEditable(false);
        outputArea.setFont(new Font("Arial", Font.PLAIN, 14));
        outputArea.setBackground(Color.DARK_GRAY);
        outputArea.setForeground(Color.WHITE);
        JScrollPane scrollPane = new JScrollPane(outputArea);

        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.Y_AXIS));
        buttonPanel.setBackground(Color.LIGHT_GRAY);

        scanButton = new JButton("Scan Directory");
        styleButton(scanButton);
        scanButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String directoryPath = JOptionPane.showInputDialog(frame, "Enter directory path to scan:");
                if (directoryPath != null && !directoryPath.isEmpty()) {
                    outputArea.setText("");
                    scanDirectory(directoryPath, outputArea);
                }
            }
        });

        deleteButton = new JButton("Delete Detected Malware");
        styleButton(deleteButton);
        deleteButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                deleteDetectedMalware(outputArea);
            }
        });

        buttonPanel.add(scanButton);
        buttonPanel.add(Box.createRigidArea(new Dimension(0, 10)));
        buttonPanel.add(deleteButton);

        frame.add(buttonPanel, BorderLayout.WEST);
        frame.add(scrollPane, BorderLayout.CENTER);
        frame.setVisible(true);
    }

    private void styleButton(JButton button) {
        button.setAlignmentX(Component.CENTER_ALIGNMENT);
        button.setFont(new Font("Arial", Font.BOLD, 16));
        button.setFocusPainted(false);
        button.setBackground(new Color(60, 179, 113));
        button.setForeground(Color.WHITE);
        button.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));
    }

    public static void main(String[] args) {
        UIManager.put("OptionPane.yesButtonText", "Yes");
        UIManager.put("OptionPane.noButtonText", "No");
        UIManager.put("OptionPane.cancelButtonText", "Cancel");
        UIManager.put("OptionPane.okButtonText", "OK");

        SwingUtilities.invokeLater(lab::new);
    }
}




