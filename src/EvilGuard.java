import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.filechooser.*;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Files;
import java.nio.file.Path;
import org.json.JSONObject;
import java.io.InputStream;


public class EvilGuard extends JFrame {
    private final Color bgColor = new Color(51, 51, 51);
    private final Color textColor = new Color(255, 255, 255);
    private final Color buttonBg = new Color(120, 113, 170);
    private final Color buttonHover = new Color(78, 82, 131);

    private JProgressBar loadingBar;
    private JLabel statusLabel;
    private JButton detailsBtn;
    private JButton uploadBtn; // Объявляем как поле класса
    private JSONObject virustotalData;
    private static final String API_KEY = "8958add810162195c3a9f355ef728c5a3652301a778f7ac405f015772032112b";

    public EvilGuard() {
        setTitle("EvilGuard");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(500, 300);
        setResizable(false);
        setLocationRelativeTo(null);
        try {
            ImageIcon originalIcon = new ImageIcon(getClass().getResource("/resources/icon.png"));
            Image scaledImage = originalIcon.getImage().getScaledInstance(64, 64, Image.SCALE_SMOOTH);
            setIconImage(scaledImage);
            
            UIManager.put("OptionPane.informationIcon", new ImageIcon(scaledImage));
            UIManager.put("OptionPane.warningIcon", new ImageIcon(scaledImage));
            UIManager.put("OptionPane.errorIcon", new ImageIcon(scaledImage));
        } catch (Exception e) {
            System.err.println("Не удалось загрузить иконку: " + e.getMessage());
        }
        try {
            // Загружаем шрифт из ресурсов
            InputStream fontStream = getClass().getResourceAsStream("/resources/fonts/Triodion-Regular.ttf");
            Font customFont = Font.createFont(Font.TRUETYPE_FONT, fontStream);
            
            // Регистрируем шрифт в графическом окружении
            GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
            ge.registerFont(customFont);
            
            // Создаем производный шрифт с нужным размером
            Font derivedFont = customFont.deriveFont(Font.PLAIN, 14);
            
            // Устанавливаем как шрифт по умолчанию для всех компонентов
            UIManager.put("Button.font", derivedFont);
            UIManager.put("Label.font", derivedFont);
            UIManager.put("TextField.font", derivedFont);
            UIManager.put("TextArea.font", derivedFont);
            UIManager.put("OptionPane.messageFont", derivedFont);
            UIManager.put("OptionPane.buttonFont", derivedFont);
            
        } catch (IOException | FontFormatException e) {
            System.err.println("Не удалось загрузить шрифт: " + e.getMessage());
        }
        initUI();
    }

    private void initUI() {
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBackground(bgColor);
        mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        // Title
        JLabel titleLabel = new JLabel("<html><h1>EvilGuard</h1><h4 style='color:rgba(255,255,255,0.5)'>Приложение написано ребятами из БАС2402</h4></html>", SwingConstants.CENTER);
        titleLabel.setForeground(textColor);
        titleLabel.setFont(new Font("Verdana", Font.BOLD, 24));
        mainPanel.add(titleLabel, BorderLayout.NORTH);

        // Loading bar
        loadingBar = new JProgressBar();
        loadingBar.setIndeterminate(true);
        loadingBar.setVisible(false);
        loadingBar.setBorder(BorderFactory.createLineBorder(textColor, 1));
        mainPanel.add(loadingBar, BorderLayout.CENTER);

        // Status label
        statusLabel = new JLabel("<html><p>-- Приложение написано на Java --</p><p>-- Интеграция с VirusTotal API --</p></html>");
        statusLabel.setForeground(new Color(255, 255, 255, 200));
        statusLabel.setFont(new Font("Verdana", Font.PLAIN, 14));
        statusLabel.setHorizontalAlignment(SwingConstants.CENTER);
        mainPanel.add(statusLabel, BorderLayout.CENTER);

        // Details button
        detailsBtn = new JButton("Показать детали отчёта");
        styleButton(detailsBtn, false);
        detailsBtn.setVisible(false);
        detailsBtn.addActionListener(e -> showVirusTotalDetails());

        // Upload button (теперь это поле класса)
        uploadBtn = new JButton("Выберите файл для проверки");
        styleButton(uploadBtn, true);
        uploadBtn.addActionListener(e -> uploadFile());

        JPanel buttonPanel = new JPanel(new GridLayout(0, 1, 0, 10));
        buttonPanel.setBackground(bgColor);
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));

        detailsBtn.setMaximumSize(new Dimension(Integer.MAX_VALUE, detailsBtn.getPreferredSize().height));
        uploadBtn.setMaximumSize(new Dimension(Integer.MAX_VALUE, uploadBtn.getPreferredSize().height));

        buttonPanel.add(detailsBtn);
        buttonPanel.add(uploadBtn);

        mainPanel.add(buttonPanel, BorderLayout.SOUTH);
        add(mainPanel);
    }

    public void styleButton(JButton button, boolean isPrimary) {
        Font buttonFont = UIManager.getFont("Button.font");
        if (buttonFont == null) {
            buttonFont = new Font("Verdana", Font.BOLD, 14);
        }
        button.setFont(buttonFont.deriveFont(Font.BOLD));
        button.setForeground(textColor);
        button.setBackground(isPrimary ? buttonBg : new Color(255, 255, 255, 50));
        button.setFocusPainted(false);
        button.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(textColor, isPrimary ? 2 : 1),
                BorderFactory.createEmptyBorder(10, 0, 10, 0) // Уменьшаем боковые отступы
        ));

        button.addMouseListener(new MouseAdapter() {
            public void mouseEntered(MouseEvent e) {
                button.setBackground(isPrimary ? buttonHover : new Color(255, 255, 255, 80));
            }
            public void mouseExited(MouseEvent e) {
                button.setBackground(isPrimary ? buttonBg : new Color(255, 255, 255, 50));
            }
        });
    }

    public void uploadFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Выберите файл");
        FileNameExtensionFilter filter = new FileNameExtensionFilter("Выберите файл (*.exe)", "exe");
        fileChooser.setFileFilter(filter);

        int returnValue = fileChooser.showOpenDialog(this);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            checkFileWithVirusTotal(selectedFile);
        }
    }

    private JSONObject getVirusTotalReport(String fileHash) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://www.virustotal.com/vtapi/v2/file/report?apikey=" + API_KEY + "&resource=" + fileHash))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, BodyHandlers.ofString());

        // Добавляем проверку ответа
        if (response.statusCode() != 200) {
            throw new IOException("VirusTotal API error: HTTP " + response.statusCode());
        }

        String responseBody = response.body();
        if (responseBody == null || responseBody.trim().isEmpty()) {
            throw new IOException("Empty response from VirusTotal");
        }

        try {
            return new JSONObject(responseBody);
        } catch (Exception e) {
            throw new IOException("Invalid JSON response: " + responseBody, e);
        }
    }

    private void checkFileWithVirusTotal(File file) {
        uploadBtn.setEnabled(false);
        loadingBar.setVisible(true);

        // Проверяем размер файла перед отправкой
        long fileSize = file.length();
        long maxSize = 32 * 1024 * 1024; // 32 MB - лимит VirusTotal

        if (fileSize > maxSize) {
            SwingUtilities.invokeLater(() -> {
                showErrorMessage("Ошибка", "Файл слишком большой (максимум 32 МБ)");
                resetUI();
            });
            return;
        }

        statusLabel.setText("Отправляем файл на VirusTotal...");

        new Thread(() -> {
            try {
                String fileHash = calculateSHA256(file.toPath());
                System.out.println("File hash: " + fileHash);

                virustotalData = getVirusTotalReport(fileHash);
                System.out.println("Initial report: " + virustotalData);

                if (virustotalData == null || virustotalData.optInt("response_code") != 1) {
                    System.out.println("Uploading file...");
                    try {
                        virustotalData = uploadFileToVirusTotal(file);
                        System.out.println("Upload response: " + virustotalData);

                        if (virustotalData.has("scan_id")) {
                            // Ждем и проверяем статус несколько раз
                            for (int i = 0; i < 5; i++) {
                                Thread.sleep(15000); // Ждем 15 секунд
                                virustotalData = getVirusTotalReport(virustotalData.getString("scan_id"));
                                if (virustotalData.optInt("response_code") == 1) {
                                    break;
                                }
                            }
                            System.out.println("Final report: " + virustotalData);
                        }
                    } catch (IOException e) {
                        if (e.getMessage().contains("HTTP 413")) {
                            throw new IOException("Файл слишком большой для VirusTotal (максимум 32 МБ)", e);
                        }
                        throw e;
                    }
                }

                SwingUtilities.invokeLater(() -> processVirusTotalResponse());

            } catch (Exception e) {
                e.printStackTrace();
                SwingUtilities.invokeLater(() -> {
                    showErrorMessage("Ошибка", e.getMessage());
                    resetUI();
                });
            }
        }).start();
    }

    private JSONObject uploadFileToVirusTotal(File file) throws IOException, InterruptedException {
        // Проверяем размер файла еще раз перед отправкой
        if (file.length() > 32 * 1024 * 1024) {
            throw new IOException("Файл слишком большой (максимум 32 МБ)");
        }

        HttpClient client = HttpClient.newHttpClient();
        String boundary = "Boundary-" + System.currentTimeMillis();
        byte[] fileBytes = Files.readAllBytes(file.toPath());

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://www.virustotal.com/vtapi/v2/file/scan"))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(ofMimeMultipartData(file.getName(), fileBytes, boundary))
                .build();

        HttpResponse<String> response = client.send(request, BodyHandlers.ofString());

        if (response.statusCode() == 413) {
            throw new IOException("HTTP 413 - Файл слишком большой");
        }
        if (response.statusCode() != 200) {
            throw new IOException("VirusTotal upload error: HTTP " + response.statusCode());
        }

        String responseBody = response.body();
        if (responseBody == null || responseBody.trim().isEmpty()) {
            throw new IOException("Empty upload response");
        }

        try {
            return new JSONObject(responseBody);
        } catch (Exception e) {
            throw new IOException("Invalid JSON upload response: " + responseBody, e);
        }
    }

    public String calculateSHA256(Path filePath) throws IOException {
        byte[] fileData = Files.readAllBytes(filePath);
        StringBuilder hexString = new StringBuilder();

        try {
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(fileData);
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
        } catch (Exception e) {
            throw new IOException("Ошибка вычисления хеша");
        }

        return hexString.toString();
    }


    public HttpRequest.BodyPublisher ofMimeMultipartData(String filename, byte[] fileContent, String boundary) {
        String partHeader = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" +
                filename + "\"\r\nContent-Type: application/octet-stream\r\n\r\n";
        String partFooter = "\r\n--" + boundary + "--\r\n";

        return HttpRequest.BodyPublishers.ofByteArrays(
                java.util.List.of(
                        partHeader.getBytes(),
                        fileContent,
                        partFooter.getBytes()
                )
        );
    }

    public void processVirusTotalResponse() {
        loadingBar.setVisible(false);
        uploadBtn.setEnabled(true);

        if (virustotalData == null) {
            showErrorMessage("Ошибка", "Не удалось получить данные от VirusTotal");
            return;
        }

        int positives = virustotalData.optInt("positives", 0);
        int total = virustotalData.optInt("total", 0);

        if (positives >= 5) {
            showCriticalMessage("Результат проверки",
                    "Обнаружено " + positives + " из " + total + " антивирусов\nФайл вредоносный!");
            detailsBtn.setVisible(true);
        } else if (positives >= 1) {
            showWarningMessage("Результат проверки",
                    "Обнаружено " + positives + " из " + total + " антивирусов\nФайл подозрительный!");
            detailsBtn.setVisible(true);
        } else {
            showInfoMessage("Результат проверки",
                    "Файл чистый (0 из " + total + " антивирусов обнаружили угрозу)");
            detailsBtn.setVisible(false);
        }

        statusLabel.setText("Проверка завершена");
    }

    public void showVirusTotalDetails() {
        if (virustotalData == null) return;

        StringBuilder report = new StringBuilder();
        report.append("Отчёт VirusTotal\n\n");
        report.append("SHA-256: ").append(virustotalData.optString("sha256", "N/A")).append("\n");
        report.append("Обнаружено: ").append(virustotalData.optInt("positives", 0))
                .append(" из ").append(virustotalData.optInt("total", 0)).append(" антивирусов\n\n");

        if (virustotalData.has("scans")) {
            report.append("Результаты сканирования:\n");
            JSONObject scans = virustotalData.getJSONObject("scans");
            for (String scanner : scans.keySet()) {
                JSONObject result = scans.getJSONObject(scanner);
                if (result.optBoolean("detected", false)) {
                    report.append("  [X] ").append(scanner).append(": ")
                            .append(result.optString("result", "Обнаружена угроза")).append("\n");
                } else {
                    report.append("  [✓] ").append(scanner).append(": Чистый\n");
                }
            }
        }

        report.append("\nСсылка на отчёт: ").append(virustotalData.optString("permalink", "N/A"));

        JTextArea textArea = new JTextArea(report.toString());
        textArea.setFont(new Font("Verdana", Font.PLAIN, 12));
        textArea.setEditable(false);
        textArea.setBackground(bgColor);
        textArea.setForeground(textColor);

        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setPreferredSize(new Dimension(600, 400));

        JOptionPane.showMessageDialog(this, scrollPane, "Отчёт VirusTotal",
                JOptionPane.INFORMATION_MESSAGE);
    }

    public void showInfoMessage(String title, String message) {
        showMessage(title, message, JOptionPane.INFORMATION_MESSAGE);
    }

    public void showWarningMessage(String title, String message) {
        showMessage(title, message, JOptionPane.WARNING_MESSAGE);
    }

    public void showCriticalMessage(String title, String message) {
        showMessage(title, message, JOptionPane.ERROR_MESSAGE);
    }

    public void showErrorMessage(String title, String message) {
        showMessage(title, message, JOptionPane.ERROR_MESSAGE);
    }

    public void showMessage(String title, String message, int messageType) {
        JTextArea textArea = new JTextArea(message);
        textArea.setFont(new Font("Verdana", Font.PLAIN, 14));
        textArea.setEditable(false);
        textArea.setBackground(bgColor);
        textArea.setForeground(textColor);
        textArea.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JOptionPane.showMessageDialog(this, textArea, title, messageType);
    }

    public void resetUI() {
        loadingBar.setVisible(false);
        uploadBtn.setEnabled(true);
        statusLabel.setText("Готово к проверке");
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new EvilGuard().setVisible(true));
    }
}