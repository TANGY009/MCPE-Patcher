package com.zeuroux.mcpepatcher;

import android.text.Editable;
import android.text.TextWatcher;

public class OnTextChange implements TextWatcher {

    public interface OnTextChanged {
        void onTextChanged();
    }
    private final OnTextChanged onTextChanged;

    public OnTextChange(OnTextChanged onTextChanged) {
        this.onTextChanged = onTextChanged;
    }

    @Override
    public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

    @Override
    public void onTextChanged(CharSequence s, int start, int before, int count) {
        onTextChanged.onTextChanged();
    }

    @Override
    public void afterTextChanged(Editable s) {}
}
