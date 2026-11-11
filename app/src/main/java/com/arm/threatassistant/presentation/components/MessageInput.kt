package com.arm.threatassistant.presentation.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.Spacer
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.sp
import com.arm.threatassistant.R

@Composable
fun MessageInput(
    value: String,
    onValueChange: (String) -> Unit,
    errorMessage: String?,
    modifier: Modifier = Modifier
) {
    val error = errorMessage
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(stringResource(R.string.hint_message)) },
        placeholder = { Text(stringResource(R.string.hint_message)) },
        singleLine = false,
        maxLines = 6,
        isError = error != null,
        supportingText = if (error != null) {
            {
                Text(
                    text = error,
                    color = MaterialTheme.colorScheme.error
                )
            }
        } else {
            null
        },
        modifier = modifier.fillMaxWidth(),
        textStyle = TextStyle(fontSize = 16.sp),
        colors = OutlinedTextFieldDefaults.colors(
            focusedContainerColor = MaterialTheme.colorScheme.surfaceContainer,
            unfocusedContainerColor = MaterialTheme.colorScheme.surface
        )
    )
}
