package com.zeuroux.mcpepatcher;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.core.content.FileProvider;
import androidx.recyclerview.widget.RecyclerView;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;

import android.os.Environment;
import android.os.Looper;
import android.provider.Settings;
import android.util.Log;
import android.view.Gravity;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.android.apksig.KeyConfig;
import com.android.apksig.util.DataSources;
import com.nareshchocha.filepickerlibrary.models.DocumentFilePickerConfig;
import com.nareshchocha.filepickerlibrary.models.PopUpConfig;
import com.nareshchocha.filepickerlibrary.models.PopUpType;
import com.nareshchocha.filepickerlibrary.ui.FilePicker;
import com.nareshchocha.filepickerlibrary.utilities.appConst.Const;
import com.zeuroux.mcpepatcher.databinding.ActivityMainBinding;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import com.android.apksig.ApkSigner;

import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.model.enums.CompressionMethod;
import net.lingala.zip4j.progress.ProgressMonitor;

public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("mcpepatcher");
    }
    String LOG_TAG = "Patching Process";
    private ActivityMainBinding binding;
    String offsets;
    File outputDirectory = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "Patcher");
    int initialTextColor;
    int red = Color.rgb(255, 0, 0);
    long time, totalTime;
    TextView progress;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                intent.setData(Uri.parse("package:" + getPackageName()));
                startActivity(intent);
            }
        }
        if (ContextCompat.checkSelfPermission(this, android.Manifest.permission.READ_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this,
                    new String[]{android.Manifest.permission.READ_EXTERNAL_STORAGE},
                    1);
        }
        super.onCreate(savedInstanceState);
        requestPermissions(new String[]{android.Manifest.permission.REQUEST_INSTALL_PACKAGES, android.Manifest.permission.READ_EXTERNAL_STORAGE, android.Manifest.permission.WRITE_EXTERNAL_STORAGE}, 1);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        binding.startPatchingApp.setOnClickListener(v -> {
            binding.installApk.setVisibility(TextView.GONE);
            if (binding.overworld.getCurrentTextColor() == red || binding.nether.getCurrentTextColor() == red || binding.end.getCurrentTextColor() == red) {
                return;
            }
            int overworld = Integer.parseInt(binding.overworld.getText().toString());
            int nether = Integer.parseInt(binding.nether.getText().toString());
            int end = Integer.parseInt(binding.end.getText().toString());
            int overworld_bottom = Integer.parseInt(binding.overworldBottom.getText().toString());
            new Thread(() -> startPatching(overworld, end, nether, overworld_bottom, false)).start();
            v.setClickable(false);
            ((Button)v).setText("Patching");
            binding.log.setText("Log:\n");
            binding.log.setOnClickListener(null);
            binding.startPatchingApk.setVisibility(TextView.GONE);
        });
        binding.startPatchingApk.setOnClickListener(v -> {
            binding.installApk.setVisibility(TextView.GONE);
            if (binding.overworld.getCurrentTextColor() == red || binding.nether.getCurrentTextColor() == red || binding.end.getCurrentTextColor() == red) {
                return;
            }
            int overworld = Integer.parseInt(binding.overworld.getText().toString());
            int nether = Integer.parseInt(binding.nether.getText().toString());
            int end = Integer.parseInt(binding.end.getText().toString());
            int overworld_bottom = Integer.parseInt(binding.overworldBottom.getText().toString());
            new Thread(() -> startPatching(overworld, end, nether, overworld_bottom, true)).start();
            v.setClickable(false);
            ((Button)v).setText("Patching");
            binding.log.setText("Log:\n");
            binding.log.setOnClickListener(null);
            binding.startPatchingApp.setVisibility(TextView.GONE);
        });
        binding.installApk.setOnClickListener(v -> {
            try {
                installApk();
            } catch (Exception e) {
                LogIt("Install", "Failed to install APK.");
                LogIt("Install", e.getLocalizedMessage());
                e.printStackTrace();
            }
        });
        binding.overworld.setText("320");
        binding.nether.setText("128");
        binding.end.setText("256");
        binding.overworldBottom.setText("-64");
        initialTextColor = binding.overworld.getCurrentTextColor();


        binding.overworld.addTextChangedListener(new OnTextChange(() -> checkErrors(binding.overworld)));
        binding.nether.addTextChangedListener(new OnTextChange(() -> checkErrors(binding.nether)));
        binding.end.addTextChangedListener(new OnTextChange(() -> checkErrors(binding.end)));

        binding.ou.setOnClickListener(v -> adjustHeight(binding.overworld, true));
        binding.od.setOnClickListener(v -> adjustHeight(binding.overworld, false));
        binding.nu.setOnClickListener(v -> adjustHeight(binding.nether, true));
        binding.nd.setOnClickListener(v -> adjustHeight(binding.nether, false));
        binding.eu.setOnClickListener(v -> adjustHeight(binding.end, true));
        binding.ed.setOnClickListener(v -> adjustHeight(binding.end, false));
        binding.obu.setOnClickListener(v -> adjustHeight(binding.overworldBottom, true));
        binding.obd.setOnClickListener(v -> adjustHeight(binding.overworldBottom, false));

        ActionBar actionBar = getSupportActionBar();
        assert actionBar != null;
        RelativeLayout relativeLayout = new RelativeLayout(getApplicationContext());
        TextView title = new TextView(getApplicationContext());
        title.setText("Build Height Patcher");
        title.setTextColor(Color.WHITE);
        title.setTextSize(20);
        title.setGravity(Gravity.START);
        RelativeLayout.LayoutParams params = new RelativeLayout.LayoutParams(
                RelativeLayout.LayoutParams.WRAP_CONTENT,
                RelativeLayout.LayoutParams.WRAP_CONTENT
        );
        title.setLayoutParams(params);
        relativeLayout.addView(title);

        progress = new TextView(getApplicationContext());
        progress.setTextColor(Color.WHITE);
        progress.setTextSize(20);
        progress.setGravity(Gravity.END);
        RelativeLayout.LayoutParams params2 = new RelativeLayout.LayoutParams(
                RelativeLayout.LayoutParams.WRAP_CONTENT,
                RelativeLayout.LayoutParams.WRAP_CONTENT
        );
        params2.addRule(RelativeLayout.ALIGN_PARENT_END);
        progress.setLayoutParams(params2);
        relativeLayout.addView(progress);
        actionBar.setDisplayOptions(ActionBar.DISPLAY_SHOW_CUSTOM);
        actionBar.setCustomView(relativeLayout);
    }
    public void installApk() {
        if (!getPackageManager().canRequestPackageInstalls()) {
            Toast.makeText(this, "Please allow the app to install unknown apps in the settings.", Toast.LENGTH_SHORT).show();
            startActivity(new Intent(android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + getPackageName())));
            return;
        }
        File apkFile = new File(outputDirectory, "Patched.apk");
        if (apkFile.exists()) {

            Uri apkUri = FileProvider.getUriForFile(this, getPackageName() + ".provider", apkFile);
            Intent installIntent = new Intent(Intent.ACTION_VIEW);
            installIntent.setDataAndType(apkUri, "application/vnd.android.package-archive");
            installIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            installIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            try {
                startActivity(installIntent);
            } catch (ActivityNotFoundException e) {
                e.printStackTrace();
            }
        } else {
            Log.e("APK Install", "APK file does not exist at the specified path.");
        }
    }
    private void checkErrors(EditText v){
        binding.error.setText("");
        if (v.getText().toString().isEmpty()) {
            binding.error.append("Height cannot be empty.\n");
            return;
        }
        int height = Integer.parseInt(v.getText().toString());
        boolean isOver = height > 2048;
        if (isOver) {
            binding.error.append("The height is over 2048.This will cause problems\n");
            v.setTextColor(Color.argb(255, 255, 255, 0));
            binding.error.setTextColor(Color.argb(255, 255, 255, 0));
        }
        boolean isDivisible = height % 16 == 0;
        if (!isDivisible) {
            binding.error.append("Height must be divisible by 16. Click < or > to round.");
            v.setTextColor(Color.argb(255, 255, 0, 0));
            binding.error.setTextColor(Color.argb(255, 255, 0, 0));
        }
        if (!isOver && isDivisible) {
            binding.error.setText("");
            v.setTextColor(initialTextColor);
        }
    }
    private void adjustHeight(TextView textView, boolean increase) {
        int height = Integer.parseInt(textView.getText().toString());
        int newHeight = increase ? height + (16 - (height % 16))
                : (height % 16 == 0) ? height - 16 : height - (height % 16);
        textView.setText(String.valueOf(newHeight));
        checkErrors((EditText) textView);
    }
    public void LogIt(String tag, String message) {
        Log.i(tag, message);
        runOnUiThread(() -> {
            if (Objects.equals(tag, "Done")) {
                binding.log.append("Total time: " + (totalTime / 1000.0) + "s\n");
                binding.installApk.setVisibility(TextView.VISIBLE);
                binding.startPatchingApp.setClickable(true);
                binding.startPatchingApp.setText("Patch App");
                binding.startPatchingApk.setClickable(true);
                binding.startPatchingApk.setText("Patch APK");
                binding.startPatchingApp.setVisibility(TextView.VISIBLE);
                binding.startPatchingApk.setVisibility(TextView.VISIBLE);
                totalTime = 0;
                return;
            }
            if (Objects.equals(tag, "Progress")) {
                progress.setText(message);
                return;
            }
            if (!message.equals("Done.") && !message.equals("Finished.") && !message.equals("Error.")) {
                binding.log.append(message + "\n");
                time = System.currentTimeMillis();
            } else {
                binding.log.append(message + " " + ((System.currentTimeMillis() - time) / 1000.0) + "s\n");
                totalTime += System.currentTimeMillis() - time;
                progress.setText("");
            }
            if (Objects.equals(tag, "Error")) {
                binding.startPatchingApp.setClickable(true);
                binding.startPatchingApp.setText("Patch App");
                binding.startPatchingApk.setClickable(true);
                binding.startPatchingApk.setText("Patch APK");
                Thread.currentThread().interrupt();
            }
            binding.log.post(() -> binding.scroll.scrollTo(0, binding.log.getBottom()));
        });

    }
    AtomicReference<String> minecraftPath = new AtomicReference<>();
    private final ActivityResultLauncher<Intent> launcher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(),
                    result -> {
                        if (result.getResultCode() == Activity.RESULT_OK) {
                            String filePath = Objects.requireNonNull(result.getData()).getStringExtra(Const.BundleExtras.FILE_PATH);
                            minecraftPath.set(filePath);
                        }
                    });
    File minecraftAPK;

    public void startPatching(int overworld, int end, int nether, int overworld_bottom, boolean fromApk) {
        Looper.prepare();
        clearDirectory(outputDirectory);
        outputDirectory.mkdirs();
        File new_path = new File(outputDirectory, "Minecraft.apk");
        if (!fromApk) {
            LogIt(LOG_TAG, "Getting Minecraft...");
            minecraftAPK = getMinecraftAPKFromInstalledApps(new_path);
        } else {
            ArrayList<String> mMimeTypesList = new ArrayList<>();
            mMimeTypesList.add("application/vnd.android.package-archive");
            LogIt(LOG_TAG, "Getting Minecraft...");
            launcher.launch(new FilePicker.Builder(this).pickDocumentFileBuild(
                    new DocumentFilePickerConfig(
                            null,
                            "Select Minecraft APK",
                            false,
                            1,
                            mMimeTypesList,
                            null,
                            null,
                            null,
                            null
                    )
            ));

            while (minecraftPath.get() == null) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
            copyFile(minecraftPath.get(), new_path.toString());
            minecraftAPK = new_path;
        }

        assert minecraftAPK != null;
        ZipFile minecraft = new ZipFile(minecraftAPK);
        minecraft.setRunInThread(true);
        LogIt(LOG_TAG, "Done.");
        PackageInfo info = getPackageManager().getPackageArchiveInfo(minecraftAPK.getAbsolutePath(), 0);
        String version = Objects.requireNonNull(info).versionName;
        LogIt(LOG_TAG, "Minecraft version: " + version);
        try {
            if (minecraft.getFileHeader("lib/arm64-v8a/libminecraftpe.so") == null) {
                LogIt("Error", "APK is not arm64-v8a");
                return;
            }
        } catch (ZipException e) {
            LogIt("Error.", "Error checking APK:" + e.getLocalizedMessage());
            return;
        }
        LogIt(LOG_TAG, "Extracting libminecraftpe.so...");
        extractLib(minecraft, getPath("libminecraftpe.so"));
        LogIt(LOG_TAG, "Done.");
        String offsetFileName = "offsets-" + version + ".txt";
        if (checkOffsetFile(minecraft, version)) {
            try {
                LogIt(LOG_TAG, "Offsets file found. Skipping finding offsets to speed up the process.");
                minecraft.extractFile(offsetFileName, outputDirectory.getPath());
                ProgressMonitor progressMonitor = minecraft.getProgressMonitor();
                while (!progressMonitor.getState().equals(ProgressMonitor.State.READY)) {}
                offsets = new String(Files.readAllBytes(getPath(offsetFileName)));
                String overworld_offset = offsets.split("\n")[0];
                String end_offset = offsets.split("\n")[1];
                String nether_offset = offsets.split("\n")[2];
                String overworld_bottom_offset = offsets.split("\n")[3];
                LogIt(LOG_TAG, "Patching libminecraftpe.so...");
                patchLib(getPath("libminecraftpe.so").toString(), overworld, end, nether, overworld_bottom, overworld_offset, end_offset, nether_offset, overworld_bottom_offset);
                LogIt(LOG_TAG, "Done.");
            } catch (IOException e) {
                LogIt("Error.", "Error reading offsets file:" + e.getLocalizedMessage());
                return;
            }
        } else {
            LogIt(LOG_TAG, "Offsets file not found. Finding offsets...");
            LogIt(LOG_TAG, "Patching libminecraftpe.so...");
            offsets = patchLib(getPath("libminecraftpe.so").toString(), overworld, end, nether, overworld_bottom);
            writeOffsets(offsets, offsetFileName);
            addFile(minecraft, getPath(offsetFileName));
            LogIt(LOG_TAG, "Done.");
        }
        LogIt(LOG_TAG, "Replacing libminecraftpe.so...");
        replaceLib(minecraft, getPath("libminecraftpe.so"));
        LogIt(LOG_TAG, "Done.");
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        LogIt(LOG_TAG, "Signing APK...");
        signApk("/Minecraft.apk", "/Patched.apk");
        LogIt(LOG_TAG, "Done.");
        LogIt("Done", "Finished.");
        cleanUp();
    }
    public void cleanUp() {
        clearDirectory(new File(getPath("lib").toString()));
        clearDirectory(new File(getPath("lib").toString()));
        new File(getPath("libminecraftpe.so").toString()).delete();
        new File(getPath("Minecraft.apk").toString()).delete();
        new File(getPath("v4_signature").toString()).delete();
    }
    public File getMinecraftAPKFromInstalledApps(File outputPath) {
        try {
            PackageInfo info = getPackageManager().getPackageInfo("com.mojang.minecraftpe", 0);
            if (info.applicationInfo.splitNames != null) {
                LogIt("Error.", "Minecraft is a split APK. use AntiSplit-M to get the non-split APK.");
                LogIt("Info.", "https://github.com/AbdurazaaqMohammed/AntiSplit-M/releases/latest");
                binding.log.setOnClickListener(v -> {
                    Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/AbdurazaaqMohammed/AntiSplit-M/releases/latest"));
                    startActivity(browserIntent);
                });
                return null;
            } else {
                String sourceDir = info.applicationInfo.sourceDir;
                if (copyFile(sourceDir, outputPath.toString())) {
                    return outputPath;
                }
            }

            return outputPath;
        } catch (PackageManager.NameNotFoundException e) {
            LogIt("Error.", "Minecraft not found.");
        }
        return null;
    }
    public native String patchLib(String libraryPath, int overworld, int end, int nether, int overworld_bottom, String overworld_offset, String end_offset, String nether_offset, String overworld_bottom_offset);
    public String patchLib(String libraryPath, int overworld, int end, int nether, int overworld_bottom) {
        return patchLib(libraryPath, overworld, end, nether, overworld_bottom, "-", "-", "-", "-");
    }
    public void extractLib(ZipFile minecraft, Path outputPath) {
        try {
            minecraft.extractFile("lib/arm64-v8a/libminecraftpe.so", outputDirectory.getPath());
            ProgressMonitor progressMonitor = minecraft.getProgressMonitor();
            while (!progressMonitor.getState().equals(ProgressMonitor.State.READY)) {
                LogIt("Progress", progressMonitor.getPercentDone() + "%");
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    LogIt("Error", "Thread interrupted while waiting for extraction to complete.");
                }
            }
            Files.move(getPath("lib/arm64-v8a/libminecraftpe.so"), outputPath);
            clearDirectory(new File(getPath("lib").toString()));
        } catch (IOException e) {
            LogIt("Error.", "Error Extracting:" + e.getLocalizedMessage());
        }
    }
    public void signApk(String apkPath, String signedApkPath) {
        try {
            KeyStore keystore;
            if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.Q) {
                Security.removeProvider("BC");
                Security.addProvider(new BouncyCastleProvider());
                keystore = KeyStore.getInstance("PKCS12", "BC");
                LogIt("Info", "Using BouncyCastle for signing on Android 10.");
            } else {
                keystore = KeyStore.getInstance("PKCS12");
            }
            InputStream keystoreInputStream = getAssets().open("bhm.jks");
            File tempKeystoreFile = new File(getCacheDir(), "bhm.jks");
            try (FileOutputStream out = new FileOutputStream(tempKeystoreFile)) {
                byte[] buffer = new byte[1024];
                int read;
                while ((read = keystoreInputStream.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                }
            }
            long apkLength = new File(outputDirectory + apkPath).length();
            File signedApk = new File(outputDirectory, signedApkPath);
            keystore.load(Files.newInputStream(tempKeystoreFile.toPath()), "build-height".toCharArray());
            String alias = "debug";
            X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
            PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, "build-height".toCharArray());
            ApkSigner.SignerConfig signerConfig = new ApkSigner.SignerConfig.Builder(
                alias, new KeyConfig.Jca(privateKey), Collections.singletonList(certificate)
            ).build();
            FileInputStream apkInputStream = new FileInputStream(outputDirectory + apkPath);
            ApkSigner.Builder builder = new ApkSigner.Builder(Collections.singletonList(signerConfig));
            builder.setInputApk(DataSources.asDataSource(apkInputStream.getChannel()));
            builder.setOutputApk(signedApk);
            builder.setCreatedBy("Zeuroux");
            builder.setV1SigningEnabled(true);
            builder.setV2SigningEnabled(true);
            builder.setV3SigningEnabled(true);
            builder.setV4SigningEnabled(true);
            builder.setV4SignatureOutputFile(new File(outputDirectory, "v4_signature"));
            ApkSigner signer = builder.build();
            signer.sign();
            LogIt("Info", "✅ APK signing completed successfully.");
            while (signedApk.length() < apkLength) {
                LogIt("Progress", (apkInputStream.getChannel().position() * 100 / apkLength) + "%");
            }
        } catch (Exception e) {
            e.printStackTrace();
            LogIt("Error.", "❌ Error Signing:" + e.getLocalizedMessage());
        }
    }
    public Path getPath(String path) {
        return outputDirectory.toPath().resolve(path);
    }
    public void clearDirectory(File directory) {
        if (directory.exists()) {
            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        clearDirectory(file);
                    } else {
                        boolean delete = file.delete();
                        if (!delete) {
                            Log.e("Delete", "Failed to delete " + file);
                        }
                    }
                }
            }
        }
        directory.delete();
    }
    public void replaceLib(ZipFile minecraft,Path libpath){
        try {
            ProgressMonitor progressMonitor = minecraft.getProgressMonitor();
            while (!progressMonitor.getState().equals(ProgressMonitor.State.READY)) {
                LogIt("Progress", progressMonitor.getPercentDone() + "%");
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    LogIt("Error", "Thread interrupted while waiting for Zip4j to be ready.");
                }
            }
            minecraft.removeFile("lib/arm64-v8a/libminecraftpe.so");
            while (!progressMonitor.getState().equals(ProgressMonitor.State.READY)) {
                LogIt("Progress", progressMonitor.getPercentDone() + "%");
                Thread.sleep(500);
            }
            ZipParameters parameters = new ZipParameters();
            parameters.setFileNameInZip("lib/arm64-v8a/libminecraftpe.so");
            minecraft.addFile(libpath.toFile(), parameters);
            while (!progressMonitor.getState().equals(ProgressMonitor.State.READY)) {
                LogIt("Progress", progressMonitor.getPercentDone() + "%");
                Thread.sleep(500);
            }
            LogIt("Info", "Successfully replaced libminecraftpe.so!");
        } catch (ZipException | InterruptedException e) {
            LogIt("Error.", "Error replacing libminecraftpe.so: " + e.getLocalizedMessage());
        }
    }
    public void addFile(ZipFile minecraft, Path file){
        try {
            minecraft.addFile(file.toFile());
        } catch (ZipException e) {
            LogIt("Error.", "Error adding file:" + e.getLocalizedMessage());
        }
    }
    public void writeOffsets(String offsets, String filename){
        try {
            Files.write(getPath(filename), offsets.getBytes());
        } catch (IOException e) {
            LogIt("Error.", "Error writing offsets:" + e.getLocalizedMessage());
        }
    }
    public boolean checkOffsetFile(ZipFile minecraft, String version){
        try {
            return minecraft.getFileHeader("offsets-" + version + ".txt") != null;
        } catch (ZipException e) {
            LogIt("Error.", "Error checking offsets file:" + e.getLocalizedMessage());
            return false;
        }
    }

    public boolean copyFile(String path, String new_path){
        try {
            FileInputStream fis = new FileInputStream(path);
            FileOutputStream fos = new FileOutputStream(new_path);
            int fileSize = (int) new File(path).length();
            byte[] buf = new byte[16384];
            int len;
            while ((len = fis.read(buf)) > 0) {
                fos.write(buf, 0, len);
                LogIt("Progress", (fis.getChannel().position() * 100 / fileSize) + "%");
            }
            fis.close();
            fos.close();
            return true;
        } catch (IOException e) {
            LogIt("Error.", "Error copying file:" + e.getLocalizedMessage());
            return false;
        }
    }
}
