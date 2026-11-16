package com.arm.threatassistant.presentation.components

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.arm.threatassistant.R

/** Decorative glossy shield-with-lock illustration. */
@Composable
fun ShieldHero(
    modifier: Modifier = Modifier,
    size: Dp = 120.dp
) {
    Image(
        painter = painterResource(R.drawable.ic_shield_lock),
        contentDescription = null,
        modifier = modifier.size(size)
    )
}
