package com.azuka.android.fingerprintactivity

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import com.azuka.android.fingerprintactivity.Fragment.BarcodeFragment
import com.azuka.android.fingerprintactivity.Fragment.ImageFragment
import com.azuka.android.fingerprintactivity.Fragment.MessageFragment
import com.azuka.android.fingerprintactivity.Fragment.NewsFragment
import kotlinx.android.synthetic.main.activity_second.*


class SecondActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_second)

        val messageFragment = MessageFragment()
        val imageFragment = ImageFragment()
        val barcodeFragment = BarcodeFragment()
        val newsFragment = NewsFragment()

        makeCurrentFragment(barcodeFragment)

        bottom_navigation.setOnNavigationItemSelectedListener {
            when (it.itemId){
                R.id.messageFragment -> makeCurrentFragment(messageFragment)
                R.id.imageFragment -> makeCurrentFragment(imageFragment)
                R.id.barcodeFragment -> makeCurrentFragment(barcodeFragment)
                R.id.newsFragment -> makeCurrentFragment(newsFragment)

            }
            true
        }
    }

    private fun makeCurrentFragment(fragment: Fragment) {
        supportFragmentManager.beginTransaction().apply {
            replace(R.id.fl_wrapper, fragment)
            commit()
        }
    }
}