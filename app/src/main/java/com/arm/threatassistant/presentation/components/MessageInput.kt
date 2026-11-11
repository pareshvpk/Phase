package com.arm.threatassistant.presentation.components

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.style.TextStyle
import androidx.compose.ui.unit.sp
import com.arm.threatassistant.R

@Composable
fun MessageInput(
    value: String,
    onValueChange: (String) -> Unit,
    errorMessage: String?,
    modifier: Modifier = Modifier
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(stringResource(R.string.hint_message)) },
        placeholder = { Text(stringResource(R.string.hint_message)) },
        singleLine = false,
        maxLines = 6,
        modifier = modifier.fillMaxWidth(),
        textStyle = TextStyle(fontSize = 16.sp),
        colors = TextFieldDefaults.outlinedTextFieldColors(
            focusedContainerColor = MaterialTheme.colorScheme.surfaceContainerColor,
            unfocusedContainerColor = MaterialTheme.colorScheme.surfaceColor
        )
    )
}
